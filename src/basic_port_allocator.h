/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file basic_port_allocator.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_BASIC_PORT_ALLOCATOR_H_
#define  __ICE_BASIC_PORT_ALLOCATOR_H_

#include <memory>
#include <string>
#include <vector>

#include <rtcbase/network.h>
#include <rtcbase/async_packet_socket.h>
#include <rtcbase/event_loop.h>
#include <rtcbase/memcheck.h>

#include "port_allocator.h"

namespace ice {

class BasicPortAllocator : public PortAllocator {
public:
    BasicPortAllocator(rtcbase::EventLoop* _el,
            rtcbase::NetworkManager* network_manager = NULL,
            PacketSocketFactory* socket_factory = NULL);
    virtual ~BasicPortAllocator();
    
    // Set to kDefaultNetworkIgnoreMask by default.
    void set_network_ignore_mask(int network_ignore_mask) override {
        // TODO(phoglund): implement support for other types than loopback.
        // See https://code.google.com/p/webrtc/issues/detail?id=4288.
        // Then remove set_network_ignore_list from NetworkManager.
        _network_ignore_mask = network_ignore_mask;
    }

    int network_ignore_mask() const { return _network_ignore_mask; }

    rtcbase::NetworkManager* network_manager() const { return _network_manager; }

    // If socket_factory() is set to NULL each PortAllocatorSession
    // creates its own socket factory.
    PacketSocketFactory* socket_factory() { return _socket_factory; }

    PortAllocatorSession* create_session_internal(
            const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd,
            const std::string& ice_unique_ip) override;

private:
    void construct(rtcbase::EventLoop* el);

private:
    rtcbase::NetworkManager* _network_manager;
    PacketSocketFactory* _socket_factory;
    std::unique_ptr<rtcbase::NetworkManager> _internal_network_manager;
    std::unique_ptr<PacketSocketFactory> _internal_socket_factory;
    bool _allow_tcp_listen;
    int _network_ignore_mask = rtcbase::k_default_network_ignore_mask;
};

enum class SessionState {
    GATHERING,  // Actively allocating ports and gathering candidates.
    CLEARED,    // Current allocation process has been stopped but may start new ones.
    STOPPED     // This session has completely stopped, no new allocation process will be started.
};

struct PortConfiguration;
class AllocationSequence;

class BasicPortAllocatorSession : public PortAllocatorSession,
                                  public rtcbase::MemCheck
{
public:
    BasicPortAllocatorSession(BasicPortAllocator* allocator,
            const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd,
            const std::string& ice_unique_ip);
    ~BasicPortAllocatorSession();
    
    virtual BasicPortAllocator* allocator() { return _allocator; }
    PacketSocketFactory* socket_factory() { return _socket_factory; }

    void start_getting_ports() override;
    bool is_stopped() const override { return _state == SessionState::STOPPED; }
    bool candidates_allocation_done() const override;

protected:
    // Starts the process of getting the port configurations.
    virtual PortConfiguration* get_port_configurations();

private:
    class PortData {
    private:
        enum State {
            STATE_INPROGRESS,  // Still gathering candidates.
            STATE_COMPLETE,    // All candidates allocated and ready for process.
            STATE_ERROR,       // Error in gathering candidates.
            STATE_PRUNED       // Pruned by higher priority ports on the same network
                               // interface. Only TURN ports may be pruned.
        };

    public:
        PortData() {}
        PortData(Port* port, AllocationSequence* seq)
            : _port(port), _sequence(seq) {}

        Port* port() const { return _port; }
        AllocationSequence* sequence() const { return _sequence; }
        bool has_pairable_candidate() const { return _has_pairable_candidate; }
        bool complete() const { return _state == STATE_COMPLETE; }
        bool error() const { return _state == STATE_ERROR; }
        bool pruned() const { return _state == STATE_PRUNED; }
        bool inprogress() const { return _state == STATE_INPROGRESS; }
        // Returns true if this port is ready to be used.
        bool ready() const {
            return _has_pairable_candidate && _state != STATE_ERROR &&
                _state != STATE_PRUNED;
        }

        void set_pruned() { _state = STATE_PRUNED; }
        void set_has_pairable_candidate(bool has_pairable_candidate) {
            if (has_pairable_candidate && _state == STATE_INPROGRESS) {
                _has_pairable_candidate = has_pairable_candidate;
            }
        }
        void set_complete() {
            _state = STATE_COMPLETE;
        }
        void set_error() {
            if (_state == STATE_INPROGRESS) {
                _state = STATE_ERROR;
            }
        }
        
        State state() const { return _state; }

    private:
        Port* _port = nullptr;
        AllocationSequence* _sequence = nullptr;
        bool _has_pairable_candidate = false;
        State _state = STATE_INPROGRESS;
    };

private:
    void config_ready(PortConfiguration* config);
    void allocate_ports();
    void do_allocate();
    void on_networks_changed();
    void on_allocation_sequence_objects_created();
    void add_allocated_port(Port* port, AllocationSequence* seq,
            bool prepare_address);
    void on_candidate_ready(Port* port, const Candidate& c);
    void on_port_complete(Port* port);
    void on_port_error(Port* port);
    void maybe_signal_candidates_allocation_done();
    void on_port_allocation_complete(AllocationSequence* seq);
    PortData* find_port(Port* port);
    std::vector<rtcbase::Network*> get_networks();
    
    bool check_candidate_filter(const Candidate& c) const;
    bool candidate_pairable(const Candidate& c, const Port* port) const;

private:
    BasicPortAllocator* _allocator;
    PacketSocketFactory* _socket_factory;
    bool _allocation_started;
    bool _network_manager_started;
    bool _allocation_sequences_created;
    std::vector<PortConfiguration*> _configs;
    std::vector<AllocationSequence*> _sequences;
    std::vector<PortData> _ports;
    uint32_t _candidate_filter = CF_ALL;
    bool _prune_turn_ports;
    SessionState _state = SessionState::CLEARED;

    friend class AllocationSequence;
};

// Records configuration information useful in creating ports.
// TODO(deadbeef): Rename "relay" to "turn_server" in this struct.
struct PortConfiguration {
    ServerAddresses stun_servers;
    std::string username;
    std::string password;
        
    PortConfiguration(const ServerAddresses& stun_servers,
            const std::string& username,
            const std::string& password);

    // Returns addresses of both the explicitly configured STUN servers,
    // and TURN servers that should be used as STUN servers.
    ServerAddresses get_stun_servers();
};

class UDPPort;

class AllocationSequence : public rtcbase::HasSlots<>, 
                           public rtcbase::LogTraceId 
{
public:
    enum State {
        k_init,       // Initial state.
        k_running,    // Started allocating ports.
        k_stopped,    // Stopped from running.
        k_completed,  // All ports are allocated.

        // k_init --> k_running --> {k_completed|k_stopped}
    };
    
    AllocationSequence(BasicPortAllocatorSession* session,
            rtcbase::Network* network,
            PortConfiguration* config,
            uint32_t flags);
    ~AllocationSequence() override;
    void init();
    void clear();

    State state() const { return _state; }

    // Starts and stops the sequence.  When started, it will continue allocating
    // new ports on its own timed schedule.
    void start();
    //void stop();
    
    void process_allocation();
     
    std::string to_string();

    // Signal from AllocationSequence, when it's done with allocating ports.
    // This signal is useful, when port allocation fails which doesn't result
    // in any candidates. Using this signal BasicPortAllocatorSession can send
    // its candidate discovery conclusion signal. Without this signal,
    // BasicPortAllocatorSession doesn't have any event to trigger signal. This
    // can also be achieved by starting timer in BPAS.
    rtcbase::Signal1<AllocationSequence*> signal_port_allocation_complete;

private:
    typedef std::vector<ProtocolType> ProtocolList;

    bool is_flag_set(uint32_t flag) { return ((_flags & flag) != 0); }
    void create_UDP_ports();
    
    void on_read_packet(rtcbase::AsyncPacketSocket* socket,
            const char* data,
            size_t size,
            const rtcbase::SocketAddress& remote_addr,
            const rtcbase::PacketTime& packet_time);

private:
    BasicPortAllocatorSession* _session;
    rtcbase::Network* _network;
    rtcbase::IPAddress _ip;
    PortConfiguration* _config;
    State _state;
    uint32_t _flags;
    ProtocolList _protocols;
    std::unique_ptr<rtcbase::AsyncPacketSocket> _udp_socket;
    // There will be only one udp port per AllocationSequence.
    UDPPort* _udp_port;
    int _phase;     
};

} // namespace ice

#endif  //__ICE_BASIC_PORT_ALLOCATOR_H_


