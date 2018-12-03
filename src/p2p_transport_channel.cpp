/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file p2p_transport_channel.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <algorithm>
#include <set>
#include <unistd.h>

#include <rtcbase/crc32.h>
#include <rtcbase/logging.h>
#include <rtcbase/string_encode.h>

#include "ice_common.h"
#include "p2p_transport_channel.h"

namespace {

// The minimum improvement in RTT that justifies a switch.
const int k_min_improvement = 10;

bool is_relay_relay(const ice::Connection* conn) {
    return conn->local_candidate().type() == ice::RELAY_PORT_TYPE &&
        conn->remote_candidate().type() == ice::RELAY_PORT_TYPE;
}

bool is_udp(ice::Connection* conn) {
    return conn->local_candidate().relay_protocol() == ice::UDP_PROTOCOL_NAME;
}

ice::PortInterface::CandidateOrigin get_origin(ice::PortInterface* port,
        ice::PortInterface* origin_port) 
{
    if (!origin_port) {
        return ice::PortInterface::ORIGIN_MESSAGE;
    } else if (port == origin_port) {
        return ice::PortInterface::ORIGIN_THIS_PORT;
    } else {
        return ice::PortInterface::ORIGIN_OTHER_PORT;
    }
}

} // namespace

namespace ice {

static constexpr int a_is_better = 1;
static constexpr int b_is_better = -1;

void ping_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    if (!data) {
        return;
    }
    
    P2PTransportChannel* channel = (P2PTransportChannel*)(data);
    channel->on_check_and_ping();
}

P2PTransportChannel::P2PTransportChannel(const std::string& transport_name,
        int component,
        rtcbase::EventLoop* el,
        PortAllocator* allocator)
    : rtcbase::MemCheck("P2PTransportChannel"),
    _transport_name(transport_name),
    _component(component),
    _el(el),
    _allocator(allocator),
    _incoming_only(false),
    _error(0),
    _remote_ice_mode(ICEMODE_FULL),
    _ice_role(ICEROLE_UNKNOWN),
    _tiebreaker(0),
    _gathering_state(k_ice_gathering_new),
    _check_receiving_interval(MIN_CHECK_RECEIVING_INTERVAL * 5),
    _config(MIN_CHECK_RECEIVING_INTERVAL * 50 /* receiving_timeout */,
            BACKUP_CONNECTION_PING_INTERVAL,
            GATHER_ONCE /* continual_gathering_policy */,
            false /* prioritize_most_likely_candidate_pairs */,
            STRONG_AND_STABLE_WRITABLE_CONNECTION_PING_INTERVAL,
            true /* presume_writable_when_fully_relayed */,
            REGATHER_ON_FAILED_NETWORKS_INTERVAL,
            RECEIVING_SWITCHING_DELAY) 
{
    _ping_watcher = _el->create_timer(ping_cb, (void*)this, true);
}

P2PTransportChannel::~P2PTransportChannel() {
    _el->delete_timer(_ping_watcher);
    clear_destroy_connections();
}

void P2PTransportChannel::set_ice_role(IceRole ice_role) {
    if (_ice_role != ice_role) {
        _ice_role = ice_role;
        for (PortInterface* port : _ports) {
            port->set_ice_role(ice_role);
        }
        /*
        // Update role on pruned ports as well, because they may still have
        // connections alive that should be using the correct role.
        for (PortInterface* port : pruned_ports_) {
            port->SetIceRole(ice_role);
        }
        */
    }
}

void P2PTransportChannel::set_ice_unique_ip(const std::string& ip) {
    _ice_unique_ip = ip;
}

void P2PTransportChannel::set_ice_tiebreaker(uint64_t tiebreaker) {
    if (!_ports.empty() || !_pruned_ports.empty()) {
        LOG_J(LS_WARNING, this) << "Attempt to change tiebreaker after Port has been allocated.";
        return;
    }

    _tiebreaker = tiebreaker;
}

bool P2PTransportChannel::verify_ice_params(const IceParameters& ice_params) {
    // For legacy protocols.
    if (ice_params.ufrag.empty() && ice_params.pwd.empty()) {
        return true;
    }

    if (ice_params.ufrag.length() < ICE_UFRAG_MIN_LENGTH ||
            ice_params.ufrag.length() > ICE_UFRAG_MAX_LENGTH) 
    {
        return false;
    }
    
    if (ice_params.pwd.length() < ICE_PWD_MIN_LENGTH ||
            ice_params.pwd.length() > ICE_PWD_MAX_LENGTH) 
    {
        return false;
    }
    return true;
}

bool P2PTransportChannel::set_ice_parameters(const IceParameters& ice_params) {
    if (!verify_ice_params(ice_params)) {
        LOG(LS_WARNING) << "Invalid ice_params, ice-ufrag: " << ice_params.ufrag
            << ", ice-pwd: " << ice_params.pwd;
        return false;
    }

    LOG(LS_TRACE) << "Set ICE ufrag: " << ice_params.ufrag
        << " pwd: " << ice_params.pwd << " on transport "
        << transport_name();
    _ice_parameters = ice_params;

    return true;
}

bool P2PTransportChannel::set_remote_ice_parameters(const IceParameters& ice_params) {
    if (!verify_ice_params(ice_params)) {
        LOG(LS_WARNING) << "Invalid ice_params, ice-ufrag: " << ice_params.ufrag
            << ", ice-pwd: " << ice_params.pwd;
        return false;
    } 
    
    LOG(LS_TRACE) << "Received remote ICE parameters: ufrag="
        << ice_params.ufrag << ", renomination "
        << (ice_params.renomination ? "enabled" : "disabled"); 
    IceParameters* current_ice = remote_ice();
    if (!current_ice || *current_ice != ice_params) {
        // Keep the ICE credentials so that newer connections
        // are prioritized over the older ones.
        _remote_ice_parameters.push_back(ice_params);
    }

    // Update the pwd of remote candidate if needed.
    for (RemoteCandidate& candidate : _remote_candidates) {
        if (candidate.username() == ice_params.ufrag && candidate.password().empty()) {
            candidate.set_password(ice_params.pwd);
        }
    }
    // We need to update the credentials and generation for any peer reflexive
    // candidates.
    for (Connection* conn : _connections) {
        conn->maybe_set_remote_ice_credentials_and_generation(
                ice_params,
                static_cast<int>(_remote_ice_parameters.size() - 1));
    }
    // Updating the remote ICE candidate generation could change the sort order.
    sort_connections_and_update_state("remote candidate generation maybe changed");

    return true;
}

void P2PTransportChannel::set_remote_ice_mode(IceMode mode) {
    _remote_ice_mode = mode;
}

void P2PTransportChannel::start_gathering() {
    if (_ice_parameters.ufrag.empty() || _ice_parameters.pwd.empty()) {
        LOG(LS_WARNING)
            << "Cannot gather candidates because ICE parameters are empty"
            << " ufrag: " << _ice_parameters.ufrag
            << " pwd: " << _ice_parameters.pwd; 
        return;
    }
     
    // Start gathering if we never started before, or if an ICE restart occurred.
    if (_allocator_sessions.empty()) {
        if (_gathering_state != k_ice_gathering_gathering) {
            _gathering_state = k_ice_gathering_gathering; 
            signal_gathering_state(this);
        }
        add_allocator_session(_allocator->create_session(
                    transport_name(), component(), _ice_parameters.ufrag, 
                    _ice_parameters.pwd, _ice_unique_ip));
        _allocator_sessions.back()->start_getting_ports();
    }
}

void P2PTransportChannel::add_remote_candidate(const Candidate& candidate) {
    uint32_t generation = get_remote_candidate_generation(candidate);
    // If a remote candidate with a previous generation arrives, drop it.
    if (generation < remote_ice_generation()) {
        LOG_J(LS_WARNING, this) << "Dropping a remote candidate because its ufrag "
            << candidate.username()
            << " indicates it was for a previous generation.";
        return;
    }
    
    Candidate new_remote_candidate(candidate);
    new_remote_candidate.set_generation(generation);
    // ICE candidates don't need to have username and password set, but
    // the code below this (specifically, ConnectionRequest::Prepare in
    // port.cc) uses the remote candidates's username.  So, we set it
    // here.
    if (remote_ice()) {
        if (candidate.username().empty()) {
            new_remote_candidate.set_username(remote_ice()->ufrag);
        }
        if (new_remote_candidate.username() == remote_ice()->ufrag) {
            if (candidate.password().empty()) {
                new_remote_candidate.set_password(remote_ice()->pwd);
            }
        } else {
            // The candidate belongs to the next generation. Its pwd will be set
            // when the new remote ICE credentials arrive.
            LOG_J(LS_WARNING, this) << "A remote candidate arrives with an unknown ufrag: "
                << candidate.username();
        }
    }

    // If this candidate matches what was thought to be a peer reflexive
    // candidate, we need to update the candidate priority/etc.
    for (Connection* conn : _connections) {
        conn->maybe_update_peer_reflexive_candidate(new_remote_candidate);
    }

    // Create connections to this remote candidate.
    create_connections(new_remote_candidate, NULL);

    // Resort the connections list, which may have new elements.
    sort_connections_and_update_state("new candidate pairs created from a new remote candidate");
}

void P2PTransportChannel::set_ice_config(const IceConfig& config) {
    if (_config.continual_gathering_policy != config.continual_gathering_policy) {
        _config.continual_gathering_policy = config.continual_gathering_policy;
        LOG_J(LS_TRACE, this) << "Set continual_gathering_policy to "
            << _config.continual_gathering_policy;
    }

    if (config.backup_connection_ping_interval >= 0 &&
            _config.backup_connection_ping_interval !=
            config.backup_connection_ping_interval) 
    {
        _config.backup_connection_ping_interval =
            config.backup_connection_ping_interval;
        LOG_J(LS_TRACE, this) << "Set backup connection ping interval to "
            << _config.backup_connection_ping_interval << " milliseconds.";
    }

    if (config.receiving_timeout >= 0 &&
            _config.receiving_timeout != config.receiving_timeout) {
        _config.receiving_timeout = config.receiving_timeout;
        _check_receiving_interval =
            std::max(MIN_CHECK_RECEIVING_INTERVAL, _config.receiving_timeout / 10);

        for (Connection* connection : _connections) {
            connection->set_receiving_timeout(_config.receiving_timeout);
        }
        LOG_J(LS_TRACE, this) << "Set ICE receiving timeout to " << _config.receiving_timeout
            << " milliseconds";
    }

    _config.prioritize_most_likely_candidate_pairs =
        config.prioritize_most_likely_candidate_pairs;
    LOG_J(LS_TRACE, this) << "Set ping most likely connection to "
        << _config.prioritize_most_likely_candidate_pairs;

    if (config.stable_writable_connection_ping_interval >= 0 &&
            _config.stable_writable_connection_ping_interval !=
            config.stable_writable_connection_ping_interval) {
        _config.stable_writable_connection_ping_interval =
            config.stable_writable_connection_ping_interval;
        LOG_J(LS_TRACE, this) << "Set stable_writable_connection_ping_interval to "
            << _config.stable_writable_connection_ping_interval;
    }

    if (config.presume_writable_when_fully_relayed !=
            _config.presume_writable_when_fully_relayed) {
        if (!_connections.empty()) {
            LOG_J(LS_WARNING, this) << "Trying to change 'presume writable' "
                << "while connections already exist!";
        } else {
            _config.presume_writable_when_fully_relayed =
                config.presume_writable_when_fully_relayed;
            LOG_J(LS_TRACE, this) << "Set presume writable when fully relayed to "
                << _config.presume_writable_when_fully_relayed;
        }
    }

    if (config.regather_on_failed_networks_interval) {
        _config.regather_on_failed_networks_interval =
            config.regather_on_failed_networks_interval;
        LOG_J(LS_TRACE, this) << "Set regather_on_failed_networks_interval to "
            << *_config.regather_on_failed_networks_interval;
    }
    if (config.receiving_switching_delay) {
        _config.receiving_switching_delay = config.receiving_switching_delay;
        LOG_J(LS_TRACE, this) << "Set receiving_switching_delay to"
            << *_config.receiving_switching_delay;
    }

    if (_config.default_nomination_mode != config.default_nomination_mode) {
        _config.default_nomination_mode = config.default_nomination_mode;
        LOG_J(LS_TRACE, this) << "Set default nomination mode to "
            << static_cast<int>(_config.default_nomination_mode);
    }
}

const IceConfig& P2PTransportChannel::config() const {
    return _config;
}

// Send data to the other side, using our selected connection.
int P2PTransportChannel::send_packet(const char *data, size_t len,
        const rtcbase::PacketOptions& options,
        int flags) 
{
    if (flags != 0) {
        _error = EINVAL;
        return -1;
    }

    // If we don't think the connection is working yet, return ENOTCONN
    // instead of sending a packet that will probably be dropped.
    if (!ready_to_send(_selected_connection)) {
        _error = ENOTCONN;
        return -1;
    }

    _last_sent_packet_id = options.packet_id;
    int sent = _selected_connection->send(data, len, options);
    if (sent <= 0) {
        //ASSERT(sent < 0);
        _error = _selected_connection->get_error();
    }
    return sent;
}

// Set options on ourselves is simply setting options on all of our available
// port objects.
int P2PTransportChannel::set_option(rtcbase::Socket::Option opt, int value) {
    OptionMap::iterator it = _options.find(opt);
    if (it == _options.end()) {
        _options.insert(std::make_pair(opt, value));
    } else if (it->second == value) {
        return 0;
    } else {
        it->second = value;
    }

    for (PortInterface* port : _ports) {
        int val = port->set_option(opt, value);
        if (val < 0) {
            // Because this also occurs deferred, probably no point in reporting an
            // error
            LOG(WARNING) << "SetOption(" << opt << ", " << value
                << ") failed: " << port->get_error();
        }
    }
    return 0;
}

bool P2PTransportChannel::get_option(rtcbase::Socket::Option opt, int* value) {
    const auto& found = _options.find(opt);
    if (found == _options.end()) {
        return false;
    }
    *value = found->second;
    return true;
}

std::vector<Connection*>
P2PTransportChannel::get_best_writable_connection_per_network() const {
    std::vector<Connection*> connections;
    for (auto kv : get_best_connection_by_network()) {
        Connection* conn = kv.second;
        if (conn->writable() && conn->connected()) {
            connections.push_back(conn);
        }
    }
    return connections;
}

// Returns the next pingable connection to ping.  
Connection* P2PTransportChannel::find_next_pingable_connection() {
    int64_t now = rtcbase::time_millis();
    
    // Rule 1: Selected connection takes priority over non-selected ones.
    if (_selected_connection && _selected_connection->connected() &&
            _selected_connection->writable() &&
            writable_connection_past_ping_interval(_selected_connection, now)) 
    {
        return _selected_connection;
    }
    
    // Rule 2: If the channel is weak, we need to find a new writable and
    // receiving connection, probably on a different network. If there are lots of
    // connections, it may take several seconds between two pings for every
    // non-selected connection. This will cause the receiving state of those
    // connections to be false, and thus they won't be selected. This is
    // problematic for network fail-over. We want to make sure at least one
    // connection per network is pinged frequently enough in order for it to be
    // selectable. So we prioritize one connection per network.
    // Rule 2.1: Among such connections, pick the one with the earliest
    // last-ping-sent time.
    if (weak()) {
        auto selectable_connections = get_best_writable_connection_per_network();
        std::vector<Connection*> pingable_selectable_connections;
        std::copy_if(selectable_connections.begin(), selectable_connections.end(),
                std::back_inserter(pingable_selectable_connections),
                [this, now](Connection* conn) {
                return writable_connection_past_ping_interval(conn, now);
                });
        auto iter = std::min_element(pingable_selectable_connections.begin(),
                pingable_selectable_connections.end(),
                [](Connection* conn1, Connection* conn2) {
                return conn1->last_ping_sent() <
                conn2->last_ping_sent();
                });
        if (iter != pingable_selectable_connections.end()) {
            return *iter;
        }
    }
    
    // Rule 3: Triggered checks have priority over non-triggered connections.
    // Rule 3.1: Among triggered checks, oldest takes precedence.
    Connection* oldest_triggered_check =
        find_oldest_connection_needing_triggered_check(now);
    if (oldest_triggered_check) {
        return oldest_triggered_check;
    }
    
    // Rule 4: Unpinged connections have priority over pinged ones.
    // If there are unpinged and pingable connections, only ping those.
    // Otherwise, treat everything as unpinged.
    // TODO(honghaiz): Instead of adding two separate vectors, we can add a state
    // "pinged" to filter out unpinged connections.
    if (std::find_if(_unpinged_connections.begin(), _unpinged_connections.end(),
                [this, now](Connection* conn) {
                return this->is_pingable(conn, now);
                }) == _unpinged_connections.end()) 
    {
        _unpinged_connections.insert(_pinged_connections.begin(),
                _pinged_connections.end());
        _pinged_connections.clear();
    }
    
    // Among un-pinged pingable connections, "more pingable" takes precedence.
    std::vector<Connection*> pingable_connections;
    std::copy_if(_unpinged_connections.begin(), _unpinged_connections.end(),
            std::back_inserter(pingable_connections),
            [this, now](Connection* conn) { return is_pingable(conn, now); });
    auto iter =
        std::max_element(pingable_connections.begin(), pingable_connections.end(),
                [this](Connection* conn1, Connection* conn2) {
                    // Some implementations of max_element compare an
                    // element with itself.
                    if (conn1 == conn2) {
                        return false;
                    }
                    return more_pingable(conn1, conn2) == conn2;
                });
    if (iter != pingable_connections.end()) {
        return *iter;
    }
    return nullptr;
}

Connection* P2PTransportChannel::more_pingable(Connection* conn1,
        Connection* conn2) 
{
    if (_config.prioritize_most_likely_candidate_pairs) {
        Connection* most_likely_to_work_conn = most_likely_to_work(conn1, conn2);
        if (most_likely_to_work_conn) {
            return most_likely_to_work_conn;
        }
    }

    Connection* least_recently_pinged_conn = least_recently_pinged(conn1, conn2);
    if (least_recently_pinged_conn) {
        return least_recently_pinged_conn;
    }

    // During the initial state when nothing has been pinged yet, return the first
    // one in the ordered |_connections|.
    return *(std::find_if(_connections.begin(), _connections.end(),
                [conn1, conn2](Connection* conn) {
                return conn == conn1 || conn == conn2;
                }));
}

Connection* P2PTransportChannel::most_likely_to_work(Connection* conn1,
        Connection* conn2) 
{
    bool rr1 = is_relay_relay(conn1);
    bool rr2 = is_relay_relay(conn2);
    if (rr1 && !rr2) {
        return conn1;
    } else if (rr2 && !rr1) {
        return conn2;
    } else if (rr1 && rr2) {
        bool udp1 = is_udp(conn1);
        bool udp2 = is_udp(conn2);
        if (udp1 && !udp2) {
            return conn1;
        } else if (udp2 && udp1) {
            return conn2;
        }
    }
    return nullptr;
}

void P2PTransportChannel::mark_connection_pinged(Connection* conn) {
    if (conn && _pinged_connections.insert(conn).second) {
        _unpinged_connections.erase(conn);
    }
}

// Change the selected connection, and let listeners know.
void P2PTransportChannel::switch_selected_connection(Connection* conn) {
    // Note: if conn is NULL, the previous |selected_connection_| has been
    // destroyed, so don't use it.
    Connection* old_selected_connection = _selected_connection;
    _selected_connection = conn;
    if (old_selected_connection) {
        old_selected_connection->set_selected(false);
    }

    if (_selected_connection) {
        ++_nomination;
        _selected_connection->set_selected(true);
        if (old_selected_connection) {
            LOG_J(LS_NOTICE, this) << "Previous selected connection: "
                << old_selected_connection->to_string();
        }
        LOG_J(LS_NOTICE, this) << "New selected connection: "
            << _selected_connection->to_string();
        signal_selected_candidate_pair_changed(this, _selected_connection,
                _last_sent_packet_id,
                ready_to_send(_selected_connection));
        signal_route_change(this, _selected_connection->remote_candidate());
        // This is a temporary, but safe fix to webrtc issue 5705.
        // TODO(honghaiz): Make all ENOTCONN error routed through the transport
        // channel so that it knows whether the media channel is allowed to
        // send; then it will only signal ready-to-send if the media channel
        // has been disallowed to send.
        if (_selected_connection->writable()) {
            signal_ready_to_send(this);
        }
    } else {
        LOG_J(LS_NOTICE, this) << "No selected connection";
    }
}

// Warning: UpdateState should eventually be called whenever a connection
// is added, deleted, or the write state of any connection changes so that the
// transport controller will get the up-to-date channel state. However it
// should not be called too often; in the case that multiple connection states
// change, it should be called after all the connection states have changed. For
// example, we call this at the end of SortConnectionsAndUpdateState.
void P2PTransportChannel::update_state() {
    IceTransportState state = compute_state();
    if (_state != state) {
        LOG_J(LS_NOTICE, this) << "Transport channel state changed from " << static_cast<int>(_state)
            << " to " << static_cast<int>(state);
        _state = state;
        signal_state_changed(this);
    }
    
    // If our selected connection is "presumed writable" (TURN-TURN with no
    // CreatePermission required), act like we're already writable to the upper
    // layers, so they can start media quicker.
    bool writable =
        _selected_connection && (_selected_connection->writable());
    set_writable(writable);

    bool receiving = false;
    for (const Connection* connection : _connections) {
        if (connection->receiving()) {
            receiving = true;
            break;
        }
    }
    set_receiving(receiving);
}

// If all connections timed out, delete them all.
void P2PTransportChannel::handle_all_timed_out() {
    for (Connection* connection : _connections) {
        connection->destroy();
    }
}

int P2PTransportChannel::get_rtt_estimate() {
    if (_selected_connection != nullptr
            && _selected_connection->rtt_samples() > 0) 
    {
        return _selected_connection->rtt();
    } else {
        return 0;
    }
}

// A channel is considered ICE completed once there is at most one active
// connection per network and at least one active connection.
IceTransportState P2PTransportChannel::compute_state() const {
    if (!_had_connection) {
        return IceTransportState::STATE_INIT;
    }

    std::vector<Connection*> active_connections;
    for (Connection* connection : _connections) {
        if (connection->active()) {
            active_connections.push_back(connection);
        }
    }
    if (active_connections.empty()) {
        return IceTransportState::STATE_FAILED;
    }

    std::set<rtcbase::Network*> networks;
    for (Connection* connection : active_connections) {
        rtcbase::Network* network = connection->port()->network();
        if (networks.find(network) == networks.end()) {
            networks.insert(network);
        } else {
            LOG_J(LS_TRACE, this) << "Ice not completed yet for this channel as "
                << network->to_string()
                << " has more than 1 connection.";
            return IceTransportState::STATE_CONNECTING;
        }
    }

    return IceTransportState::STATE_COMPLETED;
}

void P2PTransportChannel::clear_destroy_connections() {
    // 删除已经销毁的Connection
    for (size_t i=0; i<_destroy_connections.size(); ++i) {
        delete _destroy_connections[i];
    }
    _destroy_connections.clear();
}

bool P2PTransportChannel::weak() const {
    return !_selected_connection || _selected_connection->weak();
}

bool P2PTransportChannel::ready_to_send(Connection* connection) const {
    // Note that we allow sending on an unreliable connection, because it's
    // possible that it became unreliable simply due to bad chance.
    // So this shouldn't prevent attempting to send media.
    return connection != nullptr &&
        (connection->writable() ||
         connection->write_state() == Connection::STATE_WRITE_UNRELIABLE);
}

// Monitor connection states.
void P2PTransportChannel::update_connection_states() {
    int64_t now = rtcbase::time_millis();

    // We need to copy the list of connections since some may delete themselves
    // when we call UpdateState.
    for (Connection* c : _connections) {
        c->update_state(now);
    }
}

void P2PTransportChannel::maybe_start_pinging() {  
    if (_started_pinging) {
        return;
    }
    
    int64_t now = rtcbase::time_millis();
    if (std::any_of(
                _connections.begin(), _connections.end(),
                [this, now](const Connection* c) { return is_pingable(c, now); })) 
    {
        LOG_J(LS_NOTICE, this) << "Have a pingable connection for the first time; "
            << "starting to ping.";
        
        _el->start_timer(_ping_watcher, _weak_ping_interval * 1000);
        _started_pinging = true;
    }
}

void P2PTransportChannel::on_role_conflict(PortInterface* port) {
    (void)port;
    signal_role_conflict(this);  // STUN ping will be sent when SetRole is called from Transport.
}

// When a connection's state changes, we need to figure out who to use as
// the selected connection again.  It could have become usable, or become
// unusable.
void P2PTransportChannel::on_connection_state_change(Connection* connection) {    
    (void)connection;

    // We have to unroll the stack before doing this because we may be changing
    // the state of connections while sorting.
    sort_connections_and_update_state("candidate pair state changed");
}

// We data is available, let listeners know
void P2PTransportChannel::on_read_packet(Connection* connection,
        const char* data,
        size_t len,
        const rtcbase::PacketTime& packet_time) 
{
    // Do not deliver, if packet doesn't belong to the correct transport channel.
    if (!find_connection(connection)) {
        return;
    }

    // Let the client know of an incoming packet
    signal_read_packet(this, data, len, packet_time, 0);

    // May need to switch the sending connection based on the receiving media path
    // if this is the controlled side.
    if (_ice_role == ICEROLE_CONTROLLED) {
        maybe_switch_selected_connection(connection, "data received");
    }
}

void P2PTransportChannel::on_nominated(Connection* conn) {
    if (_ice_role != ICEROLE_CONTROLLED) {
        return;
    }

    if (_selected_connection == conn) {
        return;
    }

    if (maybe_switch_selected_connection(conn,
                "nomination on the controlled side")) {
        // Now that we have selected a connection, it is time to prune other
        // connections and update the read/write state of the channel.
        sort_connections_and_update_state("nominnation on the controlled side");
    } else {
        LOG_J(LS_TRACE, this)
            << "Not switching the selected connection on controlled side yet: "
            << conn->to_string();
    }
}

void P2PTransportChannel::on_check_and_ping() {
    // 清除已经销毁的连接
    clear_destroy_connections();

    // Make sure the states of the connections are up-to-date (since this affects
    // which ones are pingable).
    update_connection_states();
    
    // When the selected connection is not receiving or not writable, or any
    // active connection has not been pinged enough times, use the weak ping
    // interval.
    bool need_more_pings_at_weak_interval = std::any_of(
            _connections.begin(), _connections.end(), [](Connection* conn) {
            return conn->active() &&
            conn->num_pings_sent() < MIN_PINGS_AT_WEAK_PING_INTERVAL;
            });
    int ping_interval = (weak() || need_more_pings_at_weak_interval)
        ? _weak_ping_interval
        : STRONG_PING_INTERVAL;
    if (rtcbase::time_millis() >= _last_ping_sent_ms + ping_interval) {
        Connection* conn = find_next_pingable_connection();    
        if (conn) {
            ping_connection(conn);
            mark_connection_pinged(conn);
        }
    }       
    
    int delay = std::min(ping_interval, _check_receiving_interval); 
    if (_cur_ping_interval != delay) {
        _cur_ping_interval = delay;
        _el->stop_timer(_ping_watcher);
        _el->start_timer(_ping_watcher, delay * 1000);
    }
}

// Compare two connections based on their writing, receiving, and connected
// states.
int P2PTransportChannel::compare_connection_states(
        const Connection* a,
        const Connection* b,
        rtcbase::Optional<int64_t> receiving_unchanged_threshold,
        bool* missed_receiving_unchanged_threshold) const 
{
    // First, prefer a connection that's writable or presumed writable over
    // one that's not writable.
    bool a_writable = a->writable();
    bool b_writable = b->writable();
    if (a_writable && !b_writable) {
        return a_is_better;
    }
    if (!a_writable && b_writable) {
        return b_is_better;
    }

    // Sort based on write-state. Better states have lower values.
    if (a->write_state() < b->write_state()) {
        return a_is_better;
    }
    if (b->write_state() < a->write_state()) {
        return b_is_better;
    }

    // We prefer a receiving connection to a non-receiving, higher-priority
    // connection when sorting connections and choosing which connection to
    // switch to.
    if (a->receiving() && !b->receiving()) {
        return a_is_better;
    }
    if (!a->receiving() && b->receiving()) {
        if (!receiving_unchanged_threshold ||
                (a->receiving_unchanged_since() <= *receiving_unchanged_threshold &&
                 b->receiving_unchanged_since() <= *receiving_unchanged_threshold)) {
            return b_is_better;
        }
        *missed_receiving_unchanged_threshold = true;
    }

    // WARNING: Some complexity here about TCP reconnecting.
    // When a TCP connection fails because of a TCP socket disconnecting, the
    // active side of the connection will attempt to reconnect for 5 seconds while
    // pretending to be writable (the connection is not set to the unwritable
    // state).  On the passive side, the connection also remains writable even
    // though it is disconnected, and a new connection is created when the active
    // side connects.  At that point, there are two TCP connections on the passive
    // side: 1. the old, disconnected one that is pretending to be writable, and
    // 2.  the new, connected one that is maybe not yet writable.  For purposes of
    // pruning, pinging, and selecting the selected connection, we want to treat
    // the new connection as "better" than the old one. We could add a method
    // called something like Connection::ImReallyBadEvenThoughImWritable, but that
    // is equivalent to the existing Connection::connected(), which we already
    // have. So, in code throughout this file, we'll check whether the connection
    // is connected() or not, and if it is not, treat it as "worse" than a
    // connected one, even though it's writable.  In the code below, we're doing
    // so to make sure we treat a new writable connection as better than an old
    // disconnected connection.

    // In the case where we reconnect TCP connections, the original best
    // connection is disconnected without changing to WRITE_TIMEOUT. In this case,
    // the new connection, when it becomes writable, should have higher priority.
    if (a->write_state() == Connection::STATE_WRITABLE &&
            b->write_state() == Connection::STATE_WRITABLE) {
        if (a->connected() && !b->connected()) {
            return a_is_better;
        }
        if (!a->connected() && b->connected()) {
            return b_is_better;
        }
    }
    return 0;
}

// Compares two connections based only on the candidate and network information.
// Returns positive if |a| is better than |b|.
int P2PTransportChannel::compare_connection_candidates(
        const Connection* a,
        const Connection* b) const 
{
    // Prefer lower network cost.
    uint32_t a_cost = a->compute_network_cost();
    uint32_t b_cost = b->compute_network_cost();
    // Smaller cost is better.
    if (a_cost < b_cost) {
        return a_is_better;
    }
    if (a_cost > b_cost) {
        return b_is_better;
    }

    // Compare connection priority. Lower values get sorted last.
    if (a->priority() > b->priority()) {
        return a_is_better;
    }
    if (a->priority() < b->priority()) {
        return b_is_better;
    }

    // If we're still tied at this point, prefer a younger generation.
    // (Younger generation means a larger generation number).
    return (a->remote_candidate().generation() + a->port()->generation()) -
        (b->remote_candidate().generation() + b->port()->generation());
}

int P2PTransportChannel::compare_connections(
        const Connection* a,
        const Connection* b,
        rtcbase::Optional<int64_t> receiving_unchanged_threshold,
        bool* missed_receiving_unchanged_threshold) const 
{
    if (a == nullptr && b == nullptr) {
        return 0;
    } else if (a != nullptr && b == nullptr) {
        return a_is_better;
    } else if (a == nullptr && b != nullptr) {
        return b_is_better;
    }

    // We prefer to switch to a writable and receiving connection over a
    // non-writable or non-receiving connection, even if the latter has
    // been nominated by the controlling side.
    int state_cmp = compare_connection_states(a, b, receiving_unchanged_threshold,
            missed_receiving_unchanged_threshold);
    if (state_cmp != 0) {
        return state_cmp;
    }

    if (_ice_role == ICEROLE_CONTROLLED) {
        // Compare the connections based on the nomination states and the last data
        // received time if this is on the controlled side.
        if (a->remote_nomination() > b->remote_nomination()) {
            return a_is_better;
        }
        if (a->remote_nomination() < b->remote_nomination()) {
            return b_is_better;
        }

        if (a->last_data_received() > b->last_data_received()) {
            return a_is_better;
        }
        if (a->last_data_received() < b->last_data_received()) {
            return b_is_better;
        }
    }

    // Compare the network cost and priority.
    return compare_connection_candidates(a, b);
}

std::map<rtcbase::Network*, Connection*>
P2PTransportChannel::get_best_connection_by_network() const {
    // |_connections| has been sorted, so the first one in the list on a given
    // network is the best connection on the network, except that the selected
    // connection is always the best connection on the network.
    std::map<rtcbase::Network*, Connection*> best_connection_by_network;
    if (_selected_connection) {
        best_connection_by_network[_selected_connection->port()->network()] =
            _selected_connection;
    }
    // TODO(honghaiz): Need to update this if |_connections| are not sorted.
    for (Connection* conn : _connections) {
        rtcbase::Network* network = conn->port()->network();
        // This only inserts when the network does not exist in the map.
        best_connection_by_network.insert(std::make_pair(network, conn));
    }
    return best_connection_by_network;
}

void P2PTransportChannel::prune_connections() {
	// We can prune any connection for which there is a connected, writable
	// connection on the same network with better or equal priority.  We leave
	// those with better priority just in case they become writable later (at
	// which point, we would prune out the current selected connection).  We leave
	// connections on other networks because they may not be using the same
	// resources and they may represent very distinct paths over which we can
	// switch. If |best_conn_on_network| is not connected, we may be reconnecting
	// a TCP connection and should not prune connections in this network.
	// See the big comment in CompareConnectionStates.
	//
	// An exception is made for connections on an "any address" network, meaning
	// not bound to any specific network interface. We don't want to keep one of
	// these alive as a backup, since it could be using the same network
	// interface as the higher-priority, selected candidate pair.
	auto best_connection_by_network = get_best_connection_by_network();
	for (Connection* conn : _connections) {
		Connection* best_conn = _selected_connection;
		if (!rtcbase::IP_is_any(conn->port()->network()->ip())) {
			// If the connection is bound to a specific network interface (not an
			// "any address" network), compare it against the best connection for
			// that network interface rather than the best connection overall. This
			// ensures that at least one connection per network will be left
			// unpruned.
			best_conn = best_connection_by_network[conn->port()->network()];
		}
		// Do not prune connections if the connection being compared against is
		// weak. Otherwise, it may delete connections prematurely.
		if (best_conn && conn != best_conn && !best_conn->weak() &&
				compare_connection_candidates(best_conn, conn) >= 0) 
        {
			conn->prune();
		}
	}
}

// Sort the available connections to find the best one.  We also monitor
// the number of available connections and the current state.
void P2PTransportChannel::sort_connections_and_update_state(const std::string& reason_to_sort) {
	// Make sure the connection states are up-to-date since this affects how they
    // will be sorted.
    update_connection_states();
 
    // Find the best alternative connection by sorting.  It is important to note
    // that amongst equal preference, writable connections, this will choose the
    // one whose estimated latency is lowest.  So it is the only one that we
    // need to consider switching to.
    std::stable_sort(_connections.begin(), _connections.end(),
            [this](const Connection* a, const Connection* b) {
            int cmp = compare_connections(
                a, b, rtcbase::Optional<int64_t>(), nullptr);
            if (cmp != 0) {
                return cmp > 0;
            }
            // Otherwise, sort based on latency estimate.
            return a->rtt() < b->rtt();
            });

    LOG_J(LS_TRACE, this) << "Sorting " << _connections.size()
        << " available connections (" << reason_to_sort << "):";
    for (size_t i = 0; i < _connections.size(); ++i) {
        LOG_J(LS_TRACE, this) << _connections[i]->to_string();
    }

    Connection* top_connection =
        (_connections.size() > 0) ? _connections[0] : nullptr;

    // If necessary, switch to the new choice. Note that |top_connection| doesn't
    // have to be writable to become the selected connection although it will
    // have higher priority if it is writable.
    maybe_switch_selected_connection(top_connection, reason_to_sort);

    // The controlled side can prune only if the selected connection has been
    // nominated because otherwise it may prune the connection that will be
    // selected by the controlling side.
    // TODO(honghaiz): This is not enough to prevent a connection from being
    // pruned too early because with aggressive nomination, the controlling side
    // will nominate every connection until it becomes writable.
    if (_ice_role == ICEROLE_CONTROLLING ||
            (_selected_connection && _selected_connection->nominated())) 
    {
        prune_connections();
    }

    // Check if all connections are timedout.
    bool all_connections_timedout = true;
    for (size_t i = 0; i < _connections.size(); ++i) {
        if (_connections[i]->write_state() != Connection::STATE_WRITE_TIMEOUT) {
            all_connections_timedout = false;
            break;
        }
    }

    // Now update the writable state of the channel with the information we have
    // so far.
    if (all_connections_timedout) {
        handle_all_timed_out();
    }

    // Update the state of this channel.
    update_state();

    // Also possibly start pinging.
    // We could start pinging if:
    // * The first connection was created.
    // * ICE credentials were provided.
    // * A TCP connection became connected.
    maybe_start_pinging(); 
}

// Creates connections from all of the ports that we care about to the given
// remote candidate.  The return value is true if we created a connection from
// the origin port.
bool P2PTransportChannel::create_connections(const Candidate& remote_candidate,
        PortInterface* origin_port) 
{

    // If we've already seen the new remote candidate (in the current candidate
    // generation), then we shouldn't try creating connections for it.
    // We either already have a connection for it, or we previously created one
    // and then later pruned it. If we don't return, the channel will again
    // re-create any connections that were previously pruned, which will then
    // immediately be re-pruned, churning the network for no purpose.
    // This only applies to candidates received over signaling (i.e. origin_port
    // is NULL).
    if (!origin_port && is_duplicate_remote_candidate(remote_candidate)) {
        // return true to indicate success, without creating any new connections.
        return true;
    }
    
    // Add a new connection for this candidate to every port that allows such a
    // connection (i.e., if they have compatible protocols) and that does not
    // already have a connection to an equivalent candidate.  We must be careful
    // to make sure that the origin port is included, even if it was pruned,
    // since that may be the only port that can create this connection.
    bool created = false;
    std::vector<PortInterface *>::reverse_iterator it;
    for (it = _ports.rbegin(); it != _ports.rend(); ++it) {
        if (create_connection(*it, remote_candidate, origin_port)) {
            if (*it == origin_port) {
                created = true;
            }
        }
    }
    
    if ((origin_port != NULL) &&
            std::find(_ports.begin(), _ports.end(), origin_port) == _ports.end()) {
        if (create_connection(origin_port, remote_candidate, origin_port)) {
            created = true;
        }
    }
    
    // Remember this remote candidate so that we can add it to future ports.
    remember_remote_candidate(remote_candidate, origin_port);

    return created;
}

// Setup a connection object for the local and remote candidate combination.
// And then listen to connection object for changes.
bool P2PTransportChannel::create_connection(PortInterface* port,
        const Candidate& remote_candidate,
        PortInterface* origin_port) 
{
    if (!port->supports_protocol(remote_candidate.protocol())) {
        return false;
    }
    // Look for an existing connection with this remote address.  If one is not
    // found or it is found but the existing remote candidate has an older
    // generation, then we can create a new connection for this address.
    Connection* connection = port->get_connection(remote_candidate.address());
    if (connection == nullptr ||
            connection->remote_candidate().generation() <
            remote_candidate.generation()) 
    {
        // Don't create a connection if this is a candidate we received in a
        // message and we are not allowed to make outgoing connections.
        PortInterface::CandidateOrigin origin = get_origin(port, origin_port);
        if (origin == PortInterface::ORIGIN_MESSAGE && _incoming_only) {
            return false;
        }
        Connection* connection = port->create_connection(remote_candidate, origin);
        if (!connection) {
            return false;
        }
        add_connection(connection);
        LOG_J(LS_TRACE, this) << "Created connection with origin=" << origin << ", ("
            << _connections.size() << " total)";
        return true;
    }
    
    // No new connection was created.
    // It is not legal to try to change any of the parameters of an existing
    // connection; however, the other side can send a duplicate candidate.
    if (!remote_candidate.is_equivalent(connection->remote_candidate())) {
        LOG_J(LS_TRACE, this) << "Attempt to change a remote candidate."
            << " Existing remote candidate: "
            << connection->remote_candidate().to_string()
            << "New remote candidate: " << remote_candidate.to_string();
    }
    return false;
}

bool P2PTransportChannel::find_connection(Connection* connection) const {
    std::vector<Connection*>::const_iterator citer =
        std::find(_connections.begin(), _connections.end(), connection);
    return citer != _connections.end();
}

uint32_t P2PTransportChannel::get_remote_candidate_generation(
        const Candidate& candidate) 
{
    // If the candidate has a ufrag, use it to find the generation.
    if (!candidate.username().empty()) {
        uint32_t generation = 0;
        if (!find_remote_ice_from_ufrag(candidate.username(), &generation)) {
            // If the ufrag is not found, assume the next/future generation.
            generation = static_cast<uint32_t>(_remote_ice_parameters.size());
        }
        return generation;
    }
    // If candidate generation is set, use that.
    if (candidate.generation() > 0) {
        return candidate.generation();
    }
    // Otherwise, assume the generation from remote ice parameters.
    return remote_ice_generation();
}

// Check if remote candidate is already cached.
bool P2PTransportChannel::is_duplicate_remote_candidate(
        const Candidate& candidate) 
{
    for (size_t i = 0; i < _remote_candidates.size(); ++i) {
        if (_remote_candidates[i].is_equivalent(candidate)) {
            return true;
        }
    }
    return false;
}

// Maintain our remote candidate list, adding this new remote one.
void P2PTransportChannel::remember_remote_candidate(
        const Candidate& remote_candidate, PortInterface* origin_port) 
{
    // Remove any candidates whose generation is older than this one.  The
    // presence of a new generation indicates that the old ones are not useful.
    size_t i = 0;
    while (i < _remote_candidates.size()) {
        if (_remote_candidates[i].generation() < remote_candidate.generation()) {
            LOG(LS_TRACE) << "Pruning candidate from old generation: "
                << _remote_candidates[i].address().to_sensitive_string();
            _remote_candidates.erase(_remote_candidates.begin() + i);
        } else {
            i += 1;
        }
    }

    // Make sure this candidate is not a duplicate.
    if (is_duplicate_remote_candidate(remote_candidate)) {
        LOG(LS_TRACE) << "Duplicate candidate: " << remote_candidate.to_string();
        return;
    }

    // Try this candidate for all future ports.
    _remote_candidates.push_back(RemoteCandidate(remote_candidate, origin_port));
}

// Is the connection in a state for us to even consider pinging the other side?
// We consider a connection pingable even if it's not connected because that's
// how a TCP connection is kicked into reconnecting on the active side.
bool P2PTransportChannel::is_pingable(const Connection* conn,
        int64_t now) const 
{
    const Candidate& remote = conn->remote_candidate(); 
    // We should never get this far with an empty remote ufrag.
    if (remote.username().empty() || remote.password().empty()) {
        // If we don't have an ICE ufrag and pwd, there's no way we can ping.
        return false;
    }

    // A failed connection will not be pinged.
    if (conn->state() == IceCandidatePairState::FAILED) {
        return false;
    }

    // An never connected connection cannot be written to at all, so pinging is
    // out of the question. However, if it has become WRITABLE, it is in the
    // reconnecting state so ping is needed.
    if (!conn->connected() && !conn->writable()) {
        return false;
    }

    // If the channel is weakly connected, ping all connections.
    if (weak()) {
        return true;
    }

    // Always ping active connections regardless whether the channel is completed
    // or not, but backup connections are pinged at a slower rate.
    if (is_backup_connection(conn)) {
        return conn->rtt_samples() == 0 ||
            (now >= conn->last_ping_response_received() +
             _config.backup_connection_ping_interval);
    }
    // Don't ping inactive non-backup connections.
    if (!conn->active()) {
        return false;
    }

    // Do ping unwritable, active connections.
    if (!conn->writable()) {
        return true;
    }

    // Ping writable, active connections if it's been long enough since the last
    // ping.
    return writable_connection_past_ping_interval(conn, now);
}

bool P2PTransportChannel::writable_connection_past_ping_interval(
        const Connection* conn,
        int64_t now) const 
{
    int interval = calculate_active_writable_ping_interval(conn, now);
    return conn->last_ping_sent() + interval <= now;
}

int P2PTransportChannel::calculate_active_writable_ping_interval(
        const Connection* conn,
        int64_t now) const 
{
    // Ping each connection at a higher rate at least
    // MIN_PINGS_AT_WEAK_PING_INTERVAL times.
    if (conn->num_pings_sent() < MIN_PINGS_AT_WEAK_PING_INTERVAL) {
        return _weak_ping_interval;
    }

    int stable_interval = _config.stable_writable_connection_ping_interval;
    int stablizing_interval =
        std::min(stable_interval, WEAK_OR_STABILIZING_WRITABLE_CONNECTION_PING_INTERVAL);

    return (!weak() && conn->stable(now)) ? stable_interval : stablizing_interval;
}

// Apart from sending ping from |conn| this method also updates
// |use_candidate_attr| and |nomination| flags. One of the flags is set to
// nominate |conn| if this channel is in CONTROLLING.
void P2PTransportChannel::ping_connection(Connection* conn) {
    bool use_candidate_attr = false;
    uint32_t nomination = 0;
    if (_ice_role == ICEROLE_CONTROLLING) {
        bool renomination_supported = _ice_parameters.renomination &&
            !_remote_ice_parameters.empty() &&
            _remote_ice_parameters.back().renomination;
        if (renomination_supported) {
            nomination = get_nomination_attr(conn);
        } else {
            use_candidate_attr =
                get_use_candidate_attr(conn, _config.default_nomination_mode);
        }
    }
    conn->set_nomination(nomination);
    conn->set_use_candidate_attr(use_candidate_attr);
    _last_ping_sent_ms = rtcbase::time_millis();
    conn->ping(_last_ping_sent_ms);
}

uint32_t P2PTransportChannel::get_nomination_attr(Connection* conn) const {
    return (conn == _selected_connection) ? _nomination : 0;
}

// Nominate a connection based on the NominationMode.
bool P2PTransportChannel::get_use_candidate_attr(Connection* conn,
        NominationMode mode) const 
{
    switch (mode) {
        case NominationMode::REGULAR:
            // TODO(honghaiz): Implement regular nomination.
            return false;
        case NominationMode::AGGRESSIVE:
            if (_remote_ice_mode == ICEMODE_LITE) {
                return get_use_candidate_attr(conn, NominationMode::REGULAR);
            }
            return true;
        case NominationMode::SEMI_AGGRESSIVE: {
            // Nominate if
            // a) Remote is in FULL ICE AND
            //    a.1) |conn| is the selected connection OR
            //    a.2) there is no selected connection OR
            //    a.3) the selected connection is unwritable OR
            //    a.4) |conn| has higher priority than selected_connection.
            // b) Remote is in LITE ICE AND
            //    b.1) |conn| is the selected_connection AND
            //    b.2) |conn| is writable.
            bool selected = (conn == _selected_connection);
            if (_remote_ice_mode == ICEMODE_LITE) {
                return selected && conn->writable();
            }
            bool better_than_selected =
                !_selected_connection || !_selected_connection->writable() ||
                compare_connection_candidates(_selected_connection, conn) < 0;
            return selected || better_than_selected;
        }
        default:
            return false;
    }
}

// Add the allocator session to our list so that we know which sessions
// are still active.
void P2PTransportChannel::add_allocator_session(
        std::unique_ptr<PortAllocatorSession> session) 
{
    session->set_log_trace_id(get_log_trace_id());
    session->set_generation(static_cast<uint32_t>(_allocator_sessions.size()));
    session->signal_port_ready.connect(this, &P2PTransportChannel::on_port_ready);
    session->signal_candidates_ready.connect(this, &P2PTransportChannel::on_candidates_ready);
    session->signal_candidates_allocation_done.connect(
            this, &P2PTransportChannel::on_candidates_allocation_done);
    _allocator_sessions.push_back(std::move(session));
}

void P2PTransportChannel::add_connection(Connection* connection) {
    _connections.push_back(connection);
    _unpinged_connections.insert(connection);
    connection->set_remote_ice_mode(_remote_ice_mode);
    //connection->set_receiving_timeout(_config.receiving_timeout);
    connection->signal_read_packet.connect(
            this, &P2PTransportChannel::on_read_packet);
    //connection->SignalReadyToSend.connect(
      //      this, &P2PTransportChannel::OnReadyToSend);
    connection->signal_state_change.connect(
            this, &P2PTransportChannel::on_connection_state_change);
    connection->signal_destroyed.connect(
            this, &P2PTransportChannel::on_connection_destroyed);
    connection->signal_nominated.connect(this, &P2PTransportChannel::on_nominated);
    _had_connection = true;
}

// Determines whether we should switch the selected connection to
// |new_connection| based the writable/receiving state, the nomination state,
// and the last data received time. This prevents the controlled side from
// switching the selected connection too frequently when the controlling side
// is doing aggressive nominations. The precedence of the connection switching
// criteria is as follows:
// i) write/receiving/connected states
// ii) For controlled side,
//        a) nomination state,
//        b) last data received time.
// iii) Lower cost / higher priority.
// iv) rtt.
// To further prevent switching to high-cost networks, does not switch to
// a high-cost connection if it is not receiving.
// TODO(honghaiz): Stop the aggressive nomination on the controlling side and
// implement the ice-renomination option.
bool P2PTransportChannel::should_switch_selected_connection(
        Connection* new_connection,
        bool* missed_receiving_unchanged_threshold) const 
{
    if (!ready_to_send(new_connection) || _selected_connection == new_connection) {
        return false;
    }
     
    if (_selected_connection == nullptr) {
        return true;
    }

    // Do not switch to a connection that is not receiving if it has higher cost
    // because it may be just spuriously better.
    if (new_connection->compute_network_cost() >
            _selected_connection->compute_network_cost() &&
            !new_connection->receiving()) 
    {
        return false;
    }
    
    rtcbase::Optional<int64_t> receiving_unchanged_threshold(
            rtcbase::time_millis() - 
            _config.receiving_switching_delay.value_or(RECEIVING_SWITCHING_DELAY));
    int cmp = compare_connections(_selected_connection, new_connection,
            receiving_unchanged_threshold,
            missed_receiving_unchanged_threshold);
    if (cmp != 0) {
        return cmp < 0;
    }

    // If everything else is the same, switch only if rtt has improved by
    // a margin.
    return new_connection->rtt() <= (_selected_connection->rtt() - k_min_improvement);
}

void switching_delay(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    
    if (!data) {
        return;
    }

    P2PTransportChannel* channel = (P2PTransportChannel*)(data);
    channel->sort_connections_and_update_state(channel->switch_reason() + 
            " (after switching dampening interval)");
    el->delete_timer(w);
}

void P2PTransportChannel::run_delay(int delay, rtcbase::timer_cb_t cb) {
    rtcbase::TimerWatcher* watcher = _el->create_timer(cb, (void*)this, false);
    _el->start_timer(watcher, delay * 1000);
}

bool P2PTransportChannel::maybe_switch_selected_connection(
        Connection* new_connection,
        const std::string& reason) 
{
    bool missed_receiving_unchanged_threshold = false;
    if (should_switch_selected_connection(new_connection,
                &missed_receiving_unchanged_threshold)) {
        LOG_J(LS_NOTICE, this) << "Switching selected connection due to " << reason;
        switch_selected_connection(new_connection);
        return true;
    }
    if (missed_receiving_unchanged_threshold &&
            _config.receiving_switching_delay) {
        // If we do not switch to the connection because it missed the receiving
        // threshold, the new connection is in a better receiving state than the
        // currently selected connection. So we need to re-check whether it needs
        // to be switched at a later time.
        run_delay(*_config.receiving_switching_delay, switching_delay); 
    }
    return false;
}

// A connection is considered a backup connection if the channel state
// is completed, the connection is not the selected connection and it is active.
bool P2PTransportChannel::is_backup_connection(const Connection* conn) const {
    return _state == IceTransportState::STATE_COMPLETED && conn != _selected_connection &&
        conn->active();
}

// Find "triggered checks".  We ping first those connections that have
// received a ping but have not sent a ping since receiving it
// (last_received_ping > last_sent_ping).  But we shouldn't do
// triggered checks if the connection is already writable.
Connection* P2PTransportChannel::find_oldest_connection_needing_triggered_check(
        int64_t now) 
{
    Connection* oldest_needing_triggered_check = nullptr;
    for (auto conn : _connections) {
        if (!is_pingable(conn, now)) {
            continue;
        }
        bool needs_triggered_check =
            (!conn->writable() &&
             conn->last_ping_received() > conn->last_ping_sent());
        if (needs_triggered_check &&
                (!oldest_needing_triggered_check ||
                 (conn->last_ping_received() <
                  oldest_needing_triggered_check->last_ping_received()))) {
            oldest_needing_triggered_check = conn;
        }
    }

    if (oldest_needing_triggered_check) {
        LOG_J(LS_TRACE, this) << "Selecting connection for triggered check: "
            << oldest_needing_triggered_check->to_string();
    }
    return oldest_needing_triggered_check;
}

Connection* P2PTransportChannel::least_recently_pinged(Connection* conn1,
        Connection* conn2) 
{
    if (conn1->last_ping_sent() < conn2->last_ping_sent()) {
        return conn1;
    }
    if (conn1->last_ping_sent() > conn2->last_ping_sent()) {
        return conn2;
    }
    return nullptr;
}

// A new port is available, attempt to make connections for it
void P2PTransportChannel::on_port_ready(PortAllocatorSession *session,
        PortInterface* port) 
{
    (void)session;

    // Set in-effect options on the new port
    for (OptionMap::const_iterator it = _options.begin();
            it != _options.end();
            ++it) 
    {
        int val = port->set_option(it->first, it->second);
        if (val < 0) {
            LOG_J(LS_WARNING, port) << "SetOption(" << it->first
                << ", " << it->second
                << ") failed: " << port->get_error();
        }
    }
    
    // Remember the ports and candidates, and signal that candidates are ready.
    // The session will handle this, and send an initiate/accept/modify message
    // if one is pending.
    port->set_ice_role(_ice_role);
    port->set_ice_tiebreaker(_tiebreaker);
    _ports.push_back(port);
    port->signal_unknown_address.connect(
            this, &P2PTransportChannel::on_unknown_address);
    //port->SignalDestroyed.connect(this, &P2PTransportChannel::OnPortDestroyed);

    port->signal_role_conflict.connect(
            this, &P2PTransportChannel::on_role_conflict);
    //port->SignalSentPacket.connect(this, &P2PTransportChannel::OnSentPacket);

    // Attempt to create a connection from this new port to all of the remote
    // candidates that we were given so far.
    
    std::vector<RemoteCandidate>::iterator iter;
    for (iter = _remote_candidates.begin(); iter != _remote_candidates.end();
            ++iter) 
    {
        create_connection(port, *iter, iter->origin_port());
    }

    sort_connections_and_update_state(
            "new candidate pairs created from a new local candidate");
}

// A new candidate is available, let listeners know
void P2PTransportChannel::on_candidates_ready(
        PortAllocatorSession* session,
        const std::vector<Candidate>& candidates) 
{
    (void)session;
    for (size_t i = 0; i < candidates.size(); ++i) {
        signal_candidate_gathered(this, candidates[i]);
    }
}

void P2PTransportChannel::on_candidates_allocation_done(
        PortAllocatorSession* session) 
{
    (void)session;
    _gathering_state = k_ice_gathering_complete;
    LOG_J(LS_TRACE, this) << "P2PTransportChannel: " << transport_name() << ", component "
        << component() << " gathering complete";
    signal_gathering_state(this);
}

// Handle stun packets
void P2PTransportChannel::on_unknown_address(
        PortInterface* port,
        const rtcbase::SocketAddress& address, ProtocolType proto,
        IceMessage* stun_msg, const std::string &remote_username,
        bool port_muxed) 
{
    // Port has received a valid stun packet from an address that no Connection
    // is currently available for. See if we already have a candidate with the
    // address. If it isn't we need to create new candidate for it.

    const Candidate* candidate = nullptr;
    for (const Candidate& c : _remote_candidates) {
        if (c.username() == remote_username && c.address() == address &&
                c.protocol() == proto_to_string(proto)) 
        {
            candidate = &c;
            break;
        }
    }

    uint32_t remote_generation = 0;
    std::string remote_password;
    // The STUN binding request may arrive after setRemoteDescription and before
    // adding remote candidate, so we need to set the password to the shared
    // password and set the generation if the user name matches.
    const IceParameters* ice_param =
        find_remote_ice_from_ufrag(remote_username, &remote_generation);
    // Note: if not found, the remote_generation will still be 0.
    if (ice_param != nullptr) {
        remote_password = ice_param->pwd;
    }

    Candidate remote_candidate;
    bool remote_candidate_is_new = (candidate == nullptr);
    if (!remote_candidate_is_new) {
        remote_candidate = *candidate;
    } else {
        // Create a new candidate with this address.
        // The priority of the candidate is set to the PRIORITY attribute
        // from the request.
        const StunUInt32Attribute* priority_attr =
            stun_msg->get_uint32(STUN_ATTR_PRIORITY);
        if (!priority_attr) {
            LOG(LS_WARNING) << "P2PTransportChannel::OnUnknownAddress - "
                << "No STUN_ATTR_PRIORITY found in the "
                << "stun request message";
            port->send_binding_error_response(stun_msg, address, STUN_ERROR_BAD_REQUEST,
                    STUN_ERROR_REASON_BAD_REQUEST);
            return;
        }
        int remote_candidate_priority = priority_attr->value();

        uint16_t network_id = 0;
        uint16_t network_cost = 0;
        const StunUInt32Attribute* network_attr =
            stun_msg->get_uint32(STUN_ATTR_NETWORK_INFO);
        if (network_attr) {
            uint32_t network_info = network_attr->value();
            network_id = static_cast<uint16_t>(network_info >> 16);
            network_cost = static_cast<uint16_t>(network_info);
        }

        // RFC 5245
        // If the source transport address of the request does not match any
        // existing remote candidates, it represents a new peer reflexive remote
        // candidate.
        remote_candidate = Candidate(
                component(), proto_to_string(proto), address, remote_candidate_priority,
                remote_username, remote_password, PRFLX_PORT_TYPE, remote_generation,
                "", network_id, network_cost);

        // From RFC 5245, section-7.2.1.3:
        // The foundation of the candidate is set to an arbitrary value, different
        // from the foundation for all other remote candidates.
        remote_candidate.set_foundation(
                rtcbase::to_string<uint32_t>(rtcbase::compute_crc32(remote_candidate.id())));
    }

    // RFC5245, the agent constructs a pair whose local candidate is equal to
    // the transport address on which the STUN request was received, and a
    // remote candidate equal to the source transport address where the
    // request came from.

    // There shouldn't be an existing connection with this remote address.
    // When ports are muxed, this channel might get multiple unknown address
    // signals. In that case if the connection is already exists, we should
    // simply ignore the signal otherwise send server error.
    if (port->get_connection(remote_candidate.address())) {
        if (port_muxed) {
            LOG(LS_TRACE) << "Connection already exists for peer reflexive "
                << "candidate: " << remote_candidate.to_string();
            return;
        } else {
            port->send_binding_error_response(stun_msg, address,
                    STUN_ERROR_SERVER_ERROR,
                    STUN_ERROR_REASON_SERVER_ERROR);
            return;
        }
    }

    Connection* connection =
        port->create_connection(remote_candidate, PortInterface::ORIGIN_THIS_PORT);
    if (!connection) {
        port->send_binding_error_response(stun_msg, address, STUN_ERROR_SERVER_ERROR,
                STUN_ERROR_REASON_SERVER_ERROR);
        return;
    }

    LOG_J(LS_TRACE, this) << "Adding connection from "
        << (remote_candidate_is_new ? "peer reflexive" : "resurrected")
        << " candidate: " << remote_candidate.to_string();
    add_connection(connection);
    connection->handle_binding_request(stun_msg);

    // Update the list of connections since we just added another.  We do this
    // after sending the response since it could (in principle) delete the
    // connection in question.
    sort_connections_and_update_state(
            "a new candidate pair created from an unknown remote address");
}

// When a connection is removed, edit it out, and then update our best
// connection.
void P2PTransportChannel::on_connection_destroyed(Connection* connection) {
    // Note: the previous _selected_connection may be destroyed by now, so don't
    // use it.

    // Remove this connection from the list.
    std::vector<Connection*>::iterator iter =
        std::find(_connections.begin(), _connections.end(), connection);
    if (iter == _connections.end()) {
        return;
    }
    _pinged_connections.erase(*iter);
    _unpinged_connections.erase(*iter);
    _connections.erase(iter);
    _destroy_connections.push_back(connection);

    LOG_J(LS_NOTICE, this) << "Removed connection ("
        << static_cast<int>(_connections.size()) << " remaining)";

    // If this is currently the selected connection, then we need to pick a new
    // one. The call to SortConnectionsAndUpdateState will pick a new one. It
    // looks at the current selected connection in order to avoid switching
    // between fairly similar ones. Since this connection is no longer an option,
    // we can just set selected to nullptr and re-choose a best assuming that
    // there was no selected connection.
    if (_selected_connection == connection) {
        LOG_J(LS_NOTICE, this) << "Selected connection destroyed. Will choose a new one.";
        switch_selected_connection(nullptr);
        sort_connections_and_update_state("selected candidate pair destroyed");
    } else {
        // If a non-selected connection was destroyed, we don't need to re-sort but
        // we do need to update state, because we could be switching to "failed" or
        // "completed".
        update_state();
    }
}

const IceParameters* P2PTransportChannel::find_remote_ice_from_ufrag(
        const std::string& ufrag,
        uint32_t* generation) 
{
    const auto& params = _remote_ice_parameters;
    auto it = std::find_if(
            params.rbegin(), params.rend(),
            [ufrag](const IceParameters& param) { return param.ufrag == ufrag; });
    if (it == params.rend()) {
        // Not found.
        return nullptr;
    }
    *generation = params.rend() - it - 1;
    return &(*it);
}

void P2PTransportChannel::set_writable(bool writable) {
    if (_writable == writable) {
        return;
    }
    LOG_J(LS_TRACE, this) << "set_writable from:" << _writable << " to "
        << writable;
    _writable = writable;
    if (_writable) {
        signal_ready_to_send(this);
    }
    signal_writable_state(this);
}

void P2PTransportChannel::set_receiving(bool receiving) {
    if (_receiving == receiving) {
        return;
    }
    _receiving = receiving;
    signal_receiving_state(this);
}

std::string P2PTransportChannel::to_string() const {
    const char RECEIVING_ABBREV[2] = { '-', 'R' };
    const char WRITABLE_ABBREV[2] = { '-', 'W' };
    std::stringstream ss;
    ss << "Channel[trace_id=" << get_log_trace_id()
       << " transport_name=" << _transport_name 
       << " component=" << _component 
       << " receiving=" << RECEIVING_ABBREV[_receiving] 
       << " writable=" << WRITABLE_ABBREV[_writable] 
       << "]";
    return ss.str();
}

} // namespace ice


