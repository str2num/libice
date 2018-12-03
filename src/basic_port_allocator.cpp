/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file basic_port_allocator.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <algorithm>
#include <string>
#include <vector>

#include <rtcbase/random.h>
#include <rtcbase/logging.h>

#include "basic_packet_socket_factory.h"
#include "ice_common.h"
#include "port.h"
#include "stun_port.h"
#include "basic_port_allocator.h"

namespace {

const int PHASE_UDP = 0;
const int PHASE_RELAY = 1;
const int PHASE_TCP = 2;
const int PHASE_SSLTCP = 3;

const int k_num_phases = 3;

} // namespace

namespace ice {

const uint32_t DISABLE_ALL_PHASES =
    PORTALLOCATOR_DISABLE_UDP | PORTALLOCATOR_DISABLE_TCP |
    PORTALLOCATOR_DISABLE_STUN | PORTALLOCATOR_DISABLE_RELAY;

///////////////////// BasicPortAllocator //////////////////

BasicPortAllocator::BasicPortAllocator(rtcbase::EventLoop* el,
        rtcbase::NetworkManager* network_manager,
        PacketSocketFactory* socket_factory)
    : _network_manager(network_manager), _socket_factory(socket_factory) 
{
    construct(el);
}

BasicPortAllocator::~BasicPortAllocator() {}

void BasicPortAllocator::construct(rtcbase::EventLoop* el) {
    _allow_tcp_listen = true;

    if (!_network_manager) {
        _internal_network_manager.reset(new rtcbase::BasicNetworkManager());
        _network_manager = _internal_network_manager.get();
    }

    if (!_socket_factory) {
        _internal_socket_factory.reset(new BasicPacketSocketFactory(el));
        _socket_factory = _internal_socket_factory.get();
    }
}

PortAllocatorSession* BasicPortAllocator::create_session_internal(
        const std::string& content_name, int component,
        const std::string& ice_ufrag, const std::string& ice_pwd,
        const std::string& ice_unique_ip) 
{
    return new BasicPortAllocatorSession(
            this, content_name, component, ice_ufrag, ice_pwd,
            ice_unique_ip);
}

///////////////// BasicPortAllocatorSession //////////////////

BasicPortAllocatorSession::BasicPortAllocatorSession(
        BasicPortAllocator* allocator,
        const std::string& content_name,
        int component,
        const std::string& ice_ufrag,
        const std::string& ice_pwd,
        const std::string& ice_unique_ip)
    : PortAllocatorSession(content_name,
            component,
            ice_ufrag,
            ice_pwd,
            allocator->flags(),
            ice_unique_ip),
    rtcbase::MemCheck("BasicPortAllocatorSession"),
    _allocator(allocator),
    _socket_factory(allocator->socket_factory()),
    _allocation_started(false),
    _network_manager_started(false),
    _allocation_sequences_created(false),
    _prune_turn_ports(allocator->prune_turn_ports()) 
{
    _allocator->network_manager()->signal_networks_changed.connect(
            this, &BasicPortAllocatorSession::on_networks_changed);
    _allocator->network_manager()->start_updating();
}

BasicPortAllocatorSession::~BasicPortAllocatorSession() {
    //_allocator->network_manager()->stop_updating();
   
    for (uint32_t i = 0; i < _sequences.size(); ++i) {
        // AllocationSequence should clear it's map entry for turn ports before
        // ports are destroyed.
        _sequences[i]->clear();
    }
    
    std::vector<PortData>::iterator it;
    for (it = _ports.begin(); it != _ports.end(); it++) {
        delete it->port();
    }
 
    for (uint32_t i = 0; i < _configs.size(); ++i) {
        delete _configs[i];
    }
    
    for (uint32_t i = 0; i < _sequences.size(); ++i) {
        delete _sequences[i];
    }
}

void BasicPortAllocatorSession::start_getting_ports() {
    _state = SessionState::GATHERING;

    // config start
    PortConfiguration* config = get_port_configurations();

    // config ready
    config_ready(config);

    LOG_J(LS_TRACE, this) << "Pruning turn ports "
        << (_prune_turn_ports ? "enabled" : "disabled");
}

bool BasicPortAllocatorSession::candidates_allocation_done() const {
    // Done only if all required AllocationSequence objects
    // are created.
    if (!_allocation_sequences_created) {
        return false;
    }

    // Check that all port allocation sequences are complete (not running).
    if (std::any_of(_sequences.begin(), _sequences.end(),
                [](const AllocationSequence* sequence) {
                return sequence->state() == AllocationSequence::k_running;
                })) {
        return false;
    }
    
    // If all allocated ports are no longer gathering, session must have got all
    // expected candidates. Session will trigger candidates allocation complete
    // signal.
    return std::none_of(_ports.begin(), _ports.end(),
            [](const PortData& port) { 
            return port.inprogress(); });
}

PortConfiguration* BasicPortAllocatorSession::get_port_configurations() {
    PortConfiguration* config = new PortConfiguration(_allocator->stun_servers(),
            ice_ufrag(),
            ice_pwd());
    return config;
}

// Adds a configuration to the list.
void BasicPortAllocatorSession::config_ready(PortConfiguration* config) {
    if (config) {
        _configs.push_back(config);
    }

    allocate_ports();
}

void BasicPortAllocatorSession::allocate_ports() {
    if (_network_manager_started) {
        do_allocate();
    }

    _allocation_started = true;
}

// For each network, see if we have a sequence that covers it already.  If not,
// create a new sequence to create the appropriate ports.
void BasicPortAllocatorSession::do_allocate() {
    bool done_signal_needed = false;
    std::vector<rtcbase::Network*> networks = get_networks();
    
    if (networks.empty()) {
        LOG(LS_WARNING) << "Machine has no networks; no ports will be allocated";
        done_signal_needed = true;
    } else {
        LOG(LS_TRACE) << "Allocate ports on " << networks.size() << " networks";
        PortConfiguration* config = _configs.empty() ? nullptr : _configs.back();
        const std::string unique_ip = ice_unique_ip();
        for (uint32_t i = 0; i < networks.size(); ++i) { 
            if (!unique_ip.empty() && networks[i]->ip().to_string() != unique_ip) {
                LOG(LS_TRACE) << "Already set unique_ip=" << unique_ip << ", ignore ip=" << networks[i]->ip().to_string();
                continue;
            }

            uint32_t sequence_flags = flags();
            if ((sequence_flags & DISABLE_ALL_PHASES) == DISABLE_ALL_PHASES) {
                // If all the ports are disabled we should just fire the allocation
                // done event and return.
                done_signal_needed = true;
                break;
            }
            
            // 暂不支持relay
            sequence_flags |= PORTALLOCATOR_DISABLE_RELAY;

            if (!(sequence_flags & PORTALLOCATOR_ENABLE_IPV6) &&
                    networks[i]->get_best_IP().family() == AF_INET6) {
                // Skip IPv6 networks unless the flag's been set.
                continue;
            }
             
            AllocationSequence* sequence =
                new AllocationSequence(this, networks[i], config, sequence_flags);
            sequence->signal_port_allocation_complete.connect(
                    this, &BasicPortAllocatorSession::on_port_allocation_complete);
            sequence->set_log_trace_id(get_log_trace_id());
            sequence->init();
            sequence->start();
            _sequences.push_back(sequence);
            done_signal_needed = true;
        }
    }
    
    if (done_signal_needed) {
        _allocation_sequences_created = true;
        maybe_signal_candidates_allocation_done();
    }
}

void BasicPortAllocatorSession::on_networks_changed() {
    /*
    std::vector<rtc::Network*> networks = GetNetworks();
    std::vector<rtc::Network*> failed_networks;
    for (AllocationSequence* sequence : sequences_) {
        // Mark the sequence as "network failed" if its network is not in
        // |networks|.
        if (!sequence->network_failed() &&
                std::find(networks.begin(), networks.end(), sequence->network()) ==
                networks.end()) {
            sequence->OnNetworkFailed();
            failed_networks.push_back(sequence->network());
        }
    }
    RemovePortsAndCandidates(failed_networks);
    */
    
    _network_manager_started = true;
    /*
    if (allocation_started_)
        DoAllocate();
    */
}

void BasicPortAllocatorSession::on_allocation_sequence_objects_created() {
    _allocation_sequences_created = true;
    // Send candidate allocation complete signal if we have no sequences.
    maybe_signal_candidates_allocation_done();
}

void BasicPortAllocatorSession::add_allocated_port(Port* port,
        AllocationSequence * seq,
        bool prepare_address) 
{
    if (!port) {
        return;
    }

    LOG_J(LS_TRACE, this) << "Adding allocated port for " << content_name();
    port->set_log_trace_id(get_log_trace_id());
    port->set_content_name(content_name());
    port->set_component(component());
    port->set_generation(generation());
   
    PortData data(port, seq);
    _ports.push_back(data);

    port->signal_candidate_ready.connect(
            this, &BasicPortAllocatorSession::on_candidate_ready);
    port->signal_port_complete.connect(this,
            &BasicPortAllocatorSession::on_port_complete);
    //port->SignalDestroyed.connect(this,
      //      &BasicPortAllocatorSession::OnPortDestroyed);
    port->signal_port_error.connect(
            this, &BasicPortAllocatorSession::on_port_error);
    LOG_J(LS_TRACE, port) << "Added port to allocator";
    
    if (prepare_address) {
        port->prepare_address();
    }
}

void BasicPortAllocatorSession::on_candidate_ready(
        Port* port, const Candidate& c) 
{
    PortData* data = find_port(port);
    if (data == NULL) {
        return;
    }
    LOG_J(LS_TRACE, port) << "Gathered candidate: " << c.to_sensitive_string();
    
    // Discarding any candidate signal if port allocation status is
    // already done with gathering.
    if (!data->inprogress()) {
        LOG_J(LS_WARNING, this)
            << "Discarding candidate because port is already done gathering.";
        return;
    }
    
    // Mark that the port has a pairable candidate, either because we have a
    // usable candidate from the port, or simply because the port is bound to the
    // any address and therefore has no host candidate. This will trigger the port
    // to start creating candidate pairs (connections) and issue connectivity
    // checks. If port has already been marked as having a pairable candidate,
    // do nothing here.
    // Note: We should check whether any candidates may become ready after this
    // because there we will check whether the candidate is generated by the ready
    // ports, which may include this port.
    if (candidate_pairable(c, port) && !data->has_pairable_candidate()) {
        data->set_has_pairable_candidate(true);
        
        // If the current port is not pruned yet, SignalPortReady.
        if (!data->pruned()) {
            LOG_J(LS_TRACE, port) << "Port ready.";
            signal_port_ready(this, port);
            port->keep_alive_until_pruned();
        }
    }
     
    if (data->ready() && check_candidate_filter(c)) {
        std::vector<Candidate> candidates;
        candidates.push_back(c);
        signal_candidates_ready(this, candidates);
    } else {
        LOG_J(LS_TRACE, this) << "Discarding candidate because it doesn't match filter.";
    }
}

void BasicPortAllocatorSession::on_port_complete(Port* port) {
    LOG_J(LS_NOTICE, port) << "Port completed gathering candidates.";
    PortData* data = find_port(port);
    if (data == NULL) {
        return;
    }

    // Ignore any late signals.
    if (!data->inprogress()) {
        return;
    }

    // Moving to COMPLETE state.
    data->set_complete();
    // Send candidate allocation complete signal if this was the last port.
    maybe_signal_candidates_allocation_done();
}

void BasicPortAllocatorSession::on_port_error(Port* port) {
    LOG_J(LS_TRACE, port) << "Port encountered error while gathering candidates.";
    PortData* data = find_port(port);
    if (NULL == data) {
        return;
    }
    // We might have already given up on this port and stopped it.
    if (!data->inprogress()) {
        return;
    }

    // SignalAddressError is currently sent from StunPort/TurnPort.
    // But this signal itself is generic.
    data->set_error();
    // Send candidate allocation complete signal if this was the last port.
    maybe_signal_candidates_allocation_done();
}

void BasicPortAllocatorSession::on_port_allocation_complete(
        AllocationSequence* seq) 
{
    (void)seq;
    // Send candidate allocation complete signal if all ports are done.
    maybe_signal_candidates_allocation_done();
}

void BasicPortAllocatorSession::maybe_signal_candidates_allocation_done() {
    if (candidates_allocation_done()) {
        if (pooled()) {
            LOG_J(LS_TRACE, this) << "All candidates gathered for pooled session.";
        } else {
            LOG_J(LS_TRACE, this) << "All candidates gathered for " << content_name() << ":"
                << component() << ":" << generation();
        }
        signal_candidates_allocation_done(this);
    }
}

BasicPortAllocatorSession::PortData* BasicPortAllocatorSession::find_port(
        Port* port) 
{
    for (std::vector<PortData>::iterator it = _ports.begin();
            it != _ports.end(); ++it) 
    {
        if (it->port() == port) {
            return &*it;
        }
    }
    return NULL;
}

std::vector<rtcbase::Network*> BasicPortAllocatorSession::get_networks() {
    std::vector<rtcbase::Network*> networks;
    rtcbase::NetworkManager* network_manager = _allocator->network_manager();
    if (network_manager == nullptr) {
        return networks;
    }
    
    // If the network permission state is BLOCKED, we just act as if the flag has
    // been passed in.
    if (network_manager->enumeration_permission() ==
            rtcbase::NetworkManager::ENUMERATION_BLOCKED) 
    {
        set_flags(flags() | PORTALLOCATOR_DISABLE_ADAPTER_ENUMERATION);
    }
    // If the adapter enumeration is disabled, we'll just bind to any address
    // instead of specific NIC. This is to ensure the same routing for http
    // traffic by OS is also used here to avoid any local or public IP leakage
    // during stun process.
    if (flags() & PORTALLOCATOR_DISABLE_ADAPTER_ENUMERATION) {
        network_manager->get_any_address_networks(&networks);
    } else {
        network_manager->get_networks(&networks);
    }
    
    // Remove ignore network
    networks.erase(std::remove_if(networks.begin(), networks.end(),
                [this](rtcbase::Network* network) {
                return _allocator->network_ignore_mask() &
                network->type();
                }),
            networks.end());
    
    // If set PORTALLOCATOR_DISABLE_COSTLY_NETWORKS, remove costly networks
    if (flags() & PORTALLOCATOR_DISABLE_COSTLY_NETWORKS) {
        uint16_t lowest_cost = rtcbase::k_network_cost_max;
        for (rtcbase::Network* network : networks) {
            lowest_cost = std::min<uint16_t>(lowest_cost, network->get_cost());
        }
        networks.erase(std::remove_if(networks.begin(), networks.end(),
                    [lowest_cost](rtcbase::Network* network) {
                    return network->get_cost() >
                    lowest_cost + rtcbase::k_network_cost_low;
                    }),
                networks.end());
    }
    return networks;
}

bool BasicPortAllocatorSession::check_candidate_filter(const Candidate& c) const {
    uint32_t filter = _candidate_filter;

    // When binding to any address, before sending packets out, the getsockname
    // returns all 0s, but after sending packets, it'll be the NIC used to
    // send. All 0s is not a valid ICE candidate address and should be filtered
    // out.
    if (c.address().is_any_IP()) {
        return false;
    }

    if (c.type() == RELAY_PORT_TYPE) {
        return ((filter & CF_RELAY) != 0);
    } else if (c.type() == SRFLX_PORT_TYPE) {
        return ((filter & CF_REFLEXIVE) != 0);
    } else if (c.type() == HOST_PORT_TYPE) {
        if ((filter & CF_REFLEXIVE) && !c.address().is_private_IP()) {
            // We allow host candidates if the filter allows server-reflexive
            // candidates and the candidate is a public IP. Because we don't generate
            // server-reflexive candidates if they have the same IP as the host
            // candidate (i.e. when the host candidate is a public IP), filtering to
            // only server-reflexive candidates won't work right when the host
            // candidates have public IPs.
            return true;
        }

        return ((filter & CF_HOST) != 0);
    }
    return false;
}

bool BasicPortAllocatorSession::candidate_pairable(const Candidate& c,
        const Port* port) const 
{
    bool candidate_signalable = check_candidate_filter(c);
    
    // When device enumeration is disabled (to prevent non-default IP addresses
    // from leaking), we ping from some local candidates even though we don't
    // signal them. However, if host candidates are also disabled (for example, to
    // prevent even default IP addresses from leaking), we still don't want to
    // ping from them, even if device enumeration is disabled.  Thus, we check for
    // both device enumeration and host candidates being disabled.
    bool network_enumeration_disabled = c.address().is_any_IP();
    bool can_ping_from_candidate =
        (port->shared_socket() || c.protocol() == TCP_PROTOCOL_NAME);
    bool host_candidates_disabled = !(_candidate_filter & CF_HOST);

    return candidate_signalable ||
        (network_enumeration_disabled && can_ping_from_candidate &&
         !host_candidates_disabled);
}

///////////////////// PortConfiguration /////////////////////

PortConfiguration::PortConfiguration(const ServerAddresses& stun_servers,
        const std::string& username,
        const std::string& password) : 
    stun_servers(stun_servers),
    username(username),
    password(password) 
{
}

ServerAddresses PortConfiguration::get_stun_servers() {
    /*
    // Every UDP TURN server should also be used as a STUN server.
    ServerAddresses turn_servers = GetRelayServerAddresses(RELAY_TURN, PROTO_UDP);
    for (const rtc::SocketAddress& turn_server : turn_servers) {
        if (stun_servers.find(turn_server) == stun_servers.end()) {
            stun_servers.insert(turn_server);
        }
    }
    */
    return stun_servers;
}

////////////////////// AllocationSequence ///////////////////////////

AllocationSequence::AllocationSequence(BasicPortAllocatorSession* session,
        rtcbase::Network* network,
        PortConfiguration* config,
        uint32_t flags)
    : _session(session),
    _network(network),
    _ip(network->get_best_IP()),
    _config(config),
    _state(k_init),
    _flags(flags),
    _udp_socket(),
    _udp_port(NULL),
    _phase(0) 
{
}

AllocationSequence::~AllocationSequence() {
}

void AllocationSequence::init() {
    _udp_socket.reset(_session->socket_factory()->create_udp_socket(
                rtcbase::SocketAddress(_ip, 0), _session->allocator()->min_port(),
                _session->allocator()->max_port()));
    if (_udp_socket) {
        _udp_socket->signal_read_packet.connect(
                this, &AllocationSequence::on_read_packet);
    }
    // Continuing if |_udp_socket| is NULL, as local TCP and RelayPort using TCP
    // are next available options to setup a communication channel.
}

void AllocationSequence::clear() {
    _udp_port = NULL;
}

void AllocationSequence::start() {
    _state = k_running;
    process_allocation();
}

void AllocationSequence::process_allocation() {
    const char* const PHASE_NAMES[k_num_phases] = {"Udp", "Relay", "Tcp"};

    // Perform all of the phases in the current step.
    LOG_J(LS_TRACE, this) << _network->to_string() << "Allocation Phase=" << PHASE_NAMES[_phase];

    switch (_phase) {
        case PHASE_UDP:
            create_UDP_ports();
            //CreateStunPorts();
            break;

        case PHASE_RELAY:
            //CreateRelayPorts();
            break;

        case PHASE_TCP:
            //CreateTCPPorts();
            _state = k_completed;
            break;
        default:
            break;
    }

    if (state() == k_running) {
        ++_phase;
        process_allocation(); 
    } else {
        // If all phases in AllocationSequence are completed, no allocation
        // steps needed further. Canceling  pending signal.
        signal_port_allocation_complete(this);
    }
}

std::string AllocationSequence::to_string() {
    std::stringstream ss;
    ss << "AllocationSequence[trace_id=" << get_log_trace_id()
       << " " << _network->to_string()
       << "]";
    return ss.str();
}

void AllocationSequence::create_UDP_ports() {
    if (is_flag_set(PORTALLOCATOR_DISABLE_UDP)) {
        LOG_J(LS_TRACE, this) << "AllocationSequence: UDP ports disabled, skipping.";
        return;
    }
    
    // 只使用shared socket模式
    if (!_udp_socket) {
        LOG_J(LS_TRACE, this) << "AllocationSequence: _udp_socket is nullptr, skipping.";
        return;
    }
    
    bool emit_local_candidate_for_anyaddress =
        !is_flag_set(PORTALLOCATOR_DISABLE_DEFAULT_LOCAL_CANDIDATE);
    UDPPort* port = UDPPort::create(
            _session->socket_factory(), _network,
            _udp_socket.get(), _session->ice_ufrag(), _session->ice_pwd(),
            _session->allocator()->origin(), emit_local_candidate_for_anyaddress);

    if (port) {
        _udp_port = port;
        //port->SignalDestroyed.connect(this, &AllocationSequence::OnPortDestroyed);
        _session->add_allocated_port(port, this, true);
    }
}

void AllocationSequence::on_read_packet(
        rtcbase::AsyncPacketSocket* socket, const char* data, size_t size,
        const rtcbase::SocketAddress& remote_addr,
        const rtcbase::PacketTime& packet_time) 
{
    if (socket != _udp_socket.get()) {
        return;
    }
 
    if (_udp_port) {
        _udp_port->handle_incoming_packet(socket, data, size, remote_addr,
                packet_time);
    }
}

} // namespace ice


