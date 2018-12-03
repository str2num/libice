/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file ice_agent.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_ICE_AGENT_H_
#define  __ICE_ICE_AGENT_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <rtcbase/log_trace_id.h>
#include <rtcbase/sigslot.h>
#include <rtcbase/event_loop.h>
#include <rtcbase/memcheck.h>
#include <rtcbase/async_packet_socket.h>

#include "ice_common.h"
#include "candidate.h"
#include "candidate_pair_interface.h"
#include "port_allocator.h"
#include "ice_transport_channel.h"

namespace ice {

class IceAgent : public rtcbase::HasSlots<>, 
                 public rtcbase::LogTraceId, 
                 public rtcbase::MemCheck 
{
public: 
    IceAgent(rtcbase::EventLoop* el, PortAllocator* port_allocator);
    virtual ~IceAgent();

    rtcbase::EventLoop* el() const { return _el; }
    PortAllocator* port_allocator() const { return _port_allocator; }

    bool add_stream(const std::string& transport_name, int component);
    void remove_stream(const std::string& transport_name, int component);
    void remove_all_streams();
    void destroy();
    
    void set_ice_config(const IceConfig& config);
    
    void set_ice_parameters(const IceParameters& ice_params);
    IceParameters get_ice_parameters();
    bool set_ice_parameters(const std::string& transport_name, 
            int component, const IceParameters& ice_params);

    void set_remote_ice_parameters(const IceParameters& ice_params);
    bool set_remote_ice_parameters(const std::string& transport_name, 
            int component, const IceParameters& ice_params);
    
    void set_ice_role(IceRole ice_role);
    IceRole get_ice_role();
    
    void set_remote_ice_mode(IceMode mode);
    void set_ice_unique_ip(const std::string& ip);
    
    // Start gathering candidates for any new transports, or transports doing an
    // ICE restart.
    void start_gathering();
    bool add_remote_candidates(const std::string& transport_name,
            const Candidates& candidates,
            std::string* err);    
     
    IceTransportState get_state(const std::string& transport_name, int component);
    IceGatheringState gathering_state(const std::string& transport_name, int component);

    int send_packet(const std::string& transport_name, int component, 
            const char* data, size_t len, 
            const rtcbase::PacketOptions& options = rtcbase::PacketOptions());
    
    // Sets a socket option. Note that not all options are
    // supported by all transport types.
    int set_option(const std::string& transport_name, int component, 
            rtcbase::Socket::Option opt, int value);
    bool get_option(const std::string& transport_name, int component, 
            rtcbase::Socket::Option opt, int* value);

    int get_rtt_estimate(const std::string& transport_name, int component); 
    int get_error(const std::string& transport_name, int component); 
    bool writable(const std::string& transport_name, int component);
    static const char* get_ice_connection_state_str(IceConnectionState state);
    std::string to_string();

    // If any channel failed => failed,
    // Else if all completed => completed,
    // Else if all connected => connected,
    // Else => connecting
    rtcbase::Signal1<IceConnectionState> signal_connection_state; 

    // channel writable state
    // (transport_name, component, writable)
    rtcbase::Signal3<const std::string&, int, bool> signal_writable_state;

    // Receiving if any channel is receiving
    rtcbase::Signal1<bool> signal_receiving;
    
    // If all channels done gathering => complete,
    // Else if any are gathering => gathering,
    // Else => new
    rtcbase::Signal1<IceGatheringState> signal_gathering_state;

    // (transport_name, candidates)
    rtcbase::Signal2<const std::string&, const Candidate&> signal_candidate_gathered; 
    
    // (transport_name, component)
    rtcbase::Signal2<const std::string&, int> signal_state_changed;

    // Signalled each time a packet is received on this stream component.
    // (transport_name, component, data, data_len, packet_time)
    rtcbase::Signal5<const std::string&, int, const char*, size_t, 
        const rtcbase::PacketTime&> signal_read_packet;

    // (transport_name, component, candidate_pair, last_sent_packet_id, ready_to_send)
    rtcbase::Signal5<const std::string&, int, CandidatePairInterface*, int, bool>
        signal_selected_candidate_pair_changed;

private:  
    std::vector<IceTransportChannel*>::iterator get_transport_channel_iterator(
            const std::string& transport_name,
            int component);
    IceTransportChannel* get_transport_channel(const std::string& transport_name,
            int component);

    std::vector<IceTransportChannel*>::const_iterator get_transport_channel_iterator(
            const std::string& transport_name,
            int component) const;
    const IceTransportChannel* get_transport_channel(const std::string& transport_name,
            int component) const;

    // Handlers for signals from Transport.
    void on_channel_writable_state(PacketTransportChannel* channel);
    void on_channel_receiving_state(PacketTransportChannel* channel);
    void on_channel_gathering_state(IceTransportChannel* channel);
    void on_channel_candidate_gathered(IceTransportChannel* channel,
            const Candidate& candidate);
    void on_channel_role_conflict(IceTransportChannel* channel);
    void on_channel_state_changed(IceTransportChannel* channel);
    void on_channel_read(PacketTransportChannel* channel, const char* data,
            size_t len, const rtcbase::PacketTime& pt, int flag);
    void on_selected_candidate_pair_changed(
            IceTransportChannel* channel,
            CandidatePairInterface* selected_candidate_pair,
            int last_sent_packet_id,
            bool ready_to_send);

    void update_aggregate_states();

private:
    rtcbase::EventLoop* _el;
    PortAllocator* _port_allocator = nullptr;
    
    std::vector<IceTransportChannel*> _channels;

    IceConnectionState _ice_connection_state = k_ice_connection_connecting;
    bool _receiving = false; 
    IceGatheringState _gathering_state = k_ice_gathering_new;

    IceConfig _ice_config;
    IceParameters _ice_params;
    IceRole _ice_role = ICEROLE_CONTROLLING;
    std::string _ice_unique_ip;
    uint64_t _ice_tiebreaker = rtcbase::create_random_id64();
};

} // namespace ice

#endif  //__ICE_ICE_AGENT_H_


