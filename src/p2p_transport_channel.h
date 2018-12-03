/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file p2p_transport_channel.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_P2P_TRANSPORT_CHANNEL_H_
#define  __ICE_P2P_TRANSPORT_CHANNEL_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <rtcbase/event_loop.h>
#include <rtcbase/constructor_magic.h>
#include <rtcbase/sigslot.h>
#include <rtcbase/optional.h>
#include <rtcbase/log_trace_id.h>
#include <rtcbase/memcheck.h>

#include "port_allocator.h"
#include "ice_common.h"
#include "ice_transport_channel.h"

namespace ice {

static const int MIN_PINGS_AT_WEAK_PING_INTERVAL = 3;

// Adds the port on which the candidate originated.
class RemoteCandidate : public Candidate {
public:
    RemoteCandidate(const Candidate& c, PortInterface* origin_port)
        : Candidate(c), _origin_port(origin_port) {}

    PortInterface* origin_port() { return _origin_port; }

private:
    PortInterface* _origin_port;
};

// P2PTransportChannel manages the candidates and connection process to keep
// two P2P clients connected to each other.
class P2PTransportChannel : public IceTransportChannel, 
                            public rtcbase::MemCheck 
{
public:
    P2PTransportChannel(const std::string& transport_name,
            int component,
            rtcbase::EventLoop* el,
            PortAllocator* allocator);
    virtual ~P2PTransportChannel();
    
    // From IceTransportInternal:
    IceTransportState get_state() const override { return _state; }
    int component() const override { return _component; }
    void set_ice_role(IceRole role) override;
    IceRole get_ice_role() const override { return _ice_role; }
    void set_ice_unique_ip(const std::string& ip) override;
    void set_ice_tiebreaker(uint64_t tiebreaker) override;
    bool set_ice_parameters(const IceParameters& ice_params) override;
    bool set_remote_ice_parameters(const IceParameters& ice_params) override;
    void set_remote_ice_mode(IceMode mode) override;
    void start_gathering() override;
    IceGatheringState gathering_state() const override { return _gathering_state; }
    void add_remote_candidate(const Candidate& candidate) override;
    //void remove_remote_candidate(const Candidate& candidate) override;
    void set_ice_config(const IceConfig& config) override;
    const IceConfig& config() const;
    
    // From PacketTransportInternal:
    const std::string& transport_name() const override { return _transport_name; } 
    bool writable() const override { return _writable; }
    bool receiving() const override { return _receiving; }
    int send_packet(const char* data, size_t len,
            const rtcbase::PacketOptions& options,
            int flags = 0) override;
    int set_option(rtcbase::Socket::Option opt, int value) override;
    bool get_option(rtcbase::Socket::Option opt, int* value) override;
    int get_error() override { return _error; }
    int get_rtt_estimate() override;

    // Public for unit tests.
    Connection* find_next_pingable_connection();
    void mark_connection_pinged(Connection* conn);
    
    // Public for unit tests.
    PortAllocatorSession* allocator_session() {
        return _allocator_sessions.back().get();
    }
  
    std::string to_string() const;
    
    std::string switch_reason() const { return _switch_reason; }
    void set_switch_reason(const std::string& reason) { _switch_reason = reason; }

private:
    void clear_destroy_connections();

    // A transport channel is weak if the current best connection is either
    // not receiving or not writable, or if there is no best connection at all.
    bool weak() const; 
    // Returns true if it's possible to send packets on |connection|.
    bool ready_to_send(Connection* connection) const;
    void update_connection_states();
    //void request_sort_and_state_update();
    // Start pinging if we haven't already started, and we now have a connection
    // that's pingable.
    void maybe_start_pinging(); 

    // The methods below return a positive value if |a| is preferable to |b|,
    // a negative value if |b| is preferable, and 0 if they're equally preferable.
    // If |receiving_unchanged_threshold| is set, then when |b| is receiving and
    // |a| is not, returns a negative value only if |b| has been in receiving
    // state and |a| has been in not receiving state since
    // |receiving_unchanged_threshold| and sets
    // |missed_receiving_unchanged_threshold| to true otherwise.
    int compare_connection_states(
            const ice::Connection* a,
            const ice::Connection* b,
            rtcbase::Optional<int64_t> receiving_unchanged_threshold,
            bool* missed_receiving_unchanged_threshold) const;
    int compare_connection_candidates(const ice::Connection* a,
            const ice::Connection* b) const;
    // Compares two connections based on the connection states
    // (writable/receiving/connected), nomination states, last data received time,
    // and static preferences. Does not include latency. Used by both sorting
    // and ShouldSwitchSelectedConnection().
    // Returns a positive value if |a| is better than |b|.
    int compare_connections(const ice::Connection* a,
            const ice::Connection* b,
            rtcbase::Optional<int64_t> receiving_unchanged_threshold,
            bool* missed_receiving_unchanged_threshold) const; 

    void sort_connections_and_update_state(const std::string& reason_to_sort);
    void switch_selected_connection(Connection* conn);
    void update_state();
    void handle_all_timed_out();
    IceTransportState compute_state() const;

    bool create_connections(const Candidate& remote_candidate,
            PortInterface* origin_port); 
    bool create_connection(PortInterface* port,
            const Candidate& remote_candidate,
            PortInterface* origin_port);
    bool find_connection(Connection* connection) const;

    uint32_t get_remote_candidate_generation(const Candidate& candidate);
    bool is_duplicate_remote_candidate(const Candidate& candidate);
    void remember_remote_candidate(const Candidate& remote_candidate,
            PortInterface* origin_port);
    bool is_pingable(const Connection* conn, int64_t now) const;
    // Whether a writable connection is past its ping interval and needs to be
    // pinged again.
    bool writable_connection_past_ping_interval(const Connection* conn,
            int64_t now) const;
    int calculate_active_writable_ping_interval(const Connection* conn,
            int64_t now) const;
    void ping_connection(Connection* conn);
    void add_allocator_session(std::unique_ptr<PortAllocatorSession> session);
    void add_connection(Connection* connection);

    void on_port_ready(PortAllocatorSession *session, PortInterface* port);
    void on_candidates_ready(PortAllocatorSession *session,
            const std::vector<Candidate>& candidates);
    void on_candidates_allocation_done(PortAllocatorSession* session);
    void on_unknown_address(PortInterface* port,
            const rtcbase::SocketAddress& addr,
            ProtocolType proto,
            IceMessage* stun_msg,
            const std::string& remote_username,
            bool port_muxed); 
    
    void on_role_conflict(PortInterface* port);
    void on_connection_state_change(Connection* connection);
    void on_read_packet(Connection* connection, const char* data, size_t len,
            const rtcbase::PacketTime& packet_time);
    void on_connection_destroyed(Connection *connection);
    void on_nominated(Connection* conn);
    void on_check_and_ping();
    
    uint32_t get_nomination_attr(Connection* conn) const;
    bool get_use_candidate_attr(Connection* conn, NominationMode mode) const;

    // Returns true if we should switch to the new connection.
    // sets |missed_receiving_unchanged_threshold| to true if either
    // the selected connection or the new connection missed its
    // receiving-unchanged-threshold.
    bool should_switch_selected_connection(
            Connection* new_connection,
            bool* missed_receiving_unchanged_threshold) const;
    // Returns true if the new_connection is selected for transmission.
    bool maybe_switch_selected_connection(Connection* new_connection,
            const std::string& reason);
    // Gets the best connection for each network.
    std::map<rtcbase::Network*, Connection*> get_best_connection_by_network() const; 
    std::vector<Connection*> get_best_writable_connection_per_network() const;
    void prune_connections();
    bool is_backup_connection(const Connection* conn) const;
    
    Connection* find_oldest_connection_needing_triggered_check(int64_t now);
    // Between |conn1| and |conn2|, this function returns the one which should
    // be pinged first.
    Connection* more_pingable(Connection* conn1, Connection* conn2);
    // Select the connection which is Relay/Relay. If both of them are,
    // UDP relay protocol takes precedence.
    Connection* most_likely_to_work(Connection* conn1, Connection* conn2);
    // Compare the last_ping_sent time and return the one least recently pinged.
    Connection* least_recently_pinged(Connection* conn1, Connection* conn2);

    bool verify_ice_params(const IceParameters& ice_params);

    // Returns the latest remote ICE parameters or nullptr if there are no remote
    // ICE parameters yet.
    IceParameters* remote_ice() {
        return _remote_ice_parameters.empty() ? nullptr
            : &_remote_ice_parameters.back();
    }
    
    // Returns the remote IceParameters and generation that match |ufrag|
    // if found, and returns nullptr otherwise.
    const IceParameters* find_remote_ice_from_ufrag(const std::string& ufrag,
            uint32_t* generation);
    
    // Returns the index of the latest remote ICE parameters, or 0 if no remote
    // ICE parameters have been received.
    uint32_t remote_ice_generation() {
        return _remote_ice_parameters.empty()
            ? 0
            : static_cast<uint32_t>(_remote_ice_parameters.size() - 1);
    }
    
    // Sets the writable state, signaling if necessary.
    void set_writable(bool writable);
    // Sets the receiving state, signaling if necessary.
    void set_receiving(bool receiving);
    
    void run_delay(int delay, rtcbase::timer_cb_t cb);
    
    friend void ping_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data);
    friend void switching_delay(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data);

private:
    std::string _transport_name;
    int _component;
    rtcbase::EventLoop* _el;
    PortAllocator* _allocator;
    bool _incoming_only;
    int _error;
    std::vector<std::unique_ptr<PortAllocatorSession> > _allocator_sessions;
    // |_ports| contains ports that are used to form new connections when
    // new remote candidates are added.
    std::vector<PortInterface*> _ports;
    // |_pruned_ports| contains ports that have been removed from |_ports| and
    // are not being used to form new connections, but that aren't yet destroyed.
    // They may have existing connections, and they still fire signals such as
    // signal_unknown_address.
    std::vector<PortInterface*> _pruned_ports; 

    // |connections_| is a sorted list with the first one always be the
    // |selected_connection_| when it's not nullptr. The combination of
    // |pinged_connections_| and |unpinged_connections_| has the same
    // connections as |connections_|. These 2 sets maintain whether a
    // connection should be pinged next or not.
    std::vector<Connection*> _connections;
    std::set<Connection*> _pinged_connections;
    std::set<Connection*> _unpinged_connections;
    std::vector<Connection*> _destroy_connections;

    Connection* _selected_connection = nullptr;

    std::vector<RemoteCandidate> _remote_candidates;
    bool _had_connection = false;  // if connections_ has ever been nonempty
    typedef std::map<rtcbase::Socket::Option, int> OptionMap;
    OptionMap _options;
    IceParameters _ice_parameters;
    std::vector<IceParameters> _remote_ice_parameters;
    IceMode _remote_ice_mode;
    IceRole _ice_role;
    std::string _ice_unique_ip;
    uint64_t _tiebreaker;
    IceGatheringState _gathering_state;
    
    int _cur_ping_interval = WEAK_PING_INTERVAL;
    int _check_receiving_interval;
    int64_t _last_ping_sent_ms = 0;
    int _weak_ping_interval = WEAK_PING_INTERVAL;
    IceTransportState _state = IceTransportState::STATE_INIT;
    IceConfig _config;
    int _last_sent_packet_id = -1;  // -1 indicates no packet was sent before.
    bool _started_pinging = false; 
    // The value put in the "nomination" attribute for the next nominated
    // connection. A zero-value indicates the connection will not be nominated.
    uint32_t _nomination = 0;
    
    bool _receiving = false;
    bool _writable = false;

    rtcbase::TimerWatcher* _ping_watcher;
    std::string _switch_reason;

    RTC_DISALLOW_COPY_AND_ASSIGN(P2PTransportChannel);
};

} // namespace ice

#endif  //__ICE_P2P_TRANSPORT_CHANNEL_H_


