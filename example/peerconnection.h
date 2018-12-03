/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file peerconnection.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __RTCAGENT_EXAM_PEERCONNECTION_H_
#define  __RTCAGENT_EXAM_PEERCONNECTION_H_

#include <iostream>

#include <ice/ice_agent.h>

namespace exam {

class PeerConnection : public rtcbase::HasSlots<> {
public:
    PeerConnection(rtcbase::EventLoop* el, ice::PortAllocator* allocator);
    virtual ~PeerConnection();
    
    ice::IceAgent* ice_agent() { return _agent; }
   
    std::string get_ice_sdp();
    const std::vector<ice::Candidate>& candidates() { return _candidates; }
    
    void set_remote_ice(const std::string& ice_sdp);
    
    int send_data(const char* data, size_t len);

private:
    void on_gathering_state(ice::IceGatheringState new_state);
    void on_candidate_gathered(const std::string& transport_name, const ice::Candidate& candidate);
    void on_ice_connection_state(ice::IceConnectionState new_state);
    void on_read_packet(const std::string& transport_name, int component, const char* data, size_t len, 
            const rtcbase::PacketTime& packet_time);

private:
    rtcbase::EventLoop* _el;
    ice::PortAllocator* _allocator;
    ice::IceAgent* _agent;

    std::vector<ice::Candidate> _candidates;
};

} // namespace exam

#endif  //__RTCAGENT_EXAM_PEERCONNECTION_H_


