/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file ice_transport_channel.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_ICE_TRANSPORT_CHANNEL_H_
#define  __ICE_ICE_TRANSPORT_CHANNEL_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <rtcbase/optional.h>
#include <rtcbase/log_trace_id.h>

#include "ice_common.h"
#include "candidate.h"
#include "candidate_pair_interface.h"
#include "packet_transport_channel.h"

namespace ice {

enum IceConnectionState {
    k_ice_connection_connecting = 0,
    k_ice_connection_failed,
    k_ice_connection_connected,  // Writable, but still checking one or more connections
    k_ice_connection_completed,
};

enum IceGatheringState {
    k_ice_gathering_new = 0,
    k_ice_gathering_gathering,
    k_ice_gathering_complete,
};

enum ContinualGatheringPolicy {
    // All port allocator sessions will stop after a writable connection is found.
    GATHER_ONCE = 0,
    // The most recent port allocator session will keep on running.
    GATHER_CONTINUALLY,
    // The most recent port allocator session will keep on running, and it will
    // try to recover connectivity if the channel becomes disconnected.
    GATHER_CONTINUALLY_AND_RECOVER,
};

// ICE Nomination mode.
enum class NominationMode {
    REGULAR,         // Nominate once per ICE restart (Not implemented yet).
    AGGRESSIVE,      // Nominate every connection except that it will behave as if
                     // REGULAR when the remote is an ICE-LITE endpoint.
    SEMI_AGGRESSIVE  // Our current implementation of the nomination algorithm.
                     // The details are described in P2PTransportChannel.
};

// Information about ICE configuration.
// TODO(deadbeef): Use rtcbase::Optional to represent unset values, instead of
// -1.
struct IceConfig {
    // The ICE connection receiving timeout value in milliseconds.
    int receiving_timeout = -1;
    // Time interval in milliseconds to ping a backup connection when the ICE
    // channel is strongly connected.
    int backup_connection_ping_interval = -1;

    ContinualGatheringPolicy continual_gathering_policy = GATHER_ONCE;

    bool gather_continually() const {
        return continual_gathering_policy == GATHER_CONTINUALLY ||
            continual_gathering_policy == GATHER_CONTINUALLY_AND_RECOVER;
    }

    // Whether we should prioritize Relay/Relay candidate when nothing
    // is writable yet.
    bool prioritize_most_likely_candidate_pairs = false;

    // Writable connections are pinged at a slower rate once stablized.
    int stable_writable_connection_ping_interval = -1;

    // If set to true, this means the ICE transport should presume TURN-to-TURN
    // candidate pairs will succeed, even before a binding response is received.
    bool presume_writable_when_fully_relayed = false;

    // Interval to check on all networks and to perform ICE regathering on any
    // active network having no connection on it.
    rtcbase::Optional<int> regather_on_failed_networks_interval;

    // The time period in which we will not switch the selected connection
    // when a new connection becomes receiving but the selected connection is not
    // in case that the selected connection may become receiving soon.
    rtcbase::Optional<int> receiving_switching_delay;

    // TODO(honghaiz): Change the default to regular nomination.
    // Default nomination mode if the remote does not support renomination.
    NominationMode default_nomination_mode = NominationMode::SEMI_AGGRESSIVE;

    IceConfig() {}
    IceConfig(int receiving_timeout_ms,
            int backup_connection_ping_interval,
            ContinualGatheringPolicy gathering_policy,
            bool prioritize_most_likely_candidate_pairs,
            int stable_writable_connection_ping_interval_ms,
            bool presume_writable_when_fully_relayed,
            int regather_on_failed_networks_interval_ms,
            int receiving_switching_delay_ms)
        : receiving_timeout(receiving_timeout_ms),
        backup_connection_ping_interval(backup_connection_ping_interval),
        continual_gathering_policy(gathering_policy),
        prioritize_most_likely_candidate_pairs(
                prioritize_most_likely_candidate_pairs),
        stable_writable_connection_ping_interval(
                stable_writable_connection_ping_interval_ms),
        presume_writable_when_fully_relayed(
                presume_writable_when_fully_relayed),
        regather_on_failed_networks_interval(
                regather_on_failed_networks_interval_ms),
        receiving_switching_delay(receiving_switching_delay_ms) {}
};

enum class IceTransportState {
    STATE_INIT,
    STATE_CONNECTING,  // Will enter this state once a connection is created
    STATE_COMPLETED,
    STATE_FAILED
};

const char* get_ice_gathering_state_str(IceGatheringState state);

class IceTransportChannel : public PacketTransportChannel,
                            public rtcbase::LogTraceId
{
public:
    IceTransportChannel();
    virtual ~IceTransportChannel() override;
    
    virtual IceTransportState get_state() const = 0;
 
    virtual IceRole get_ice_role() const = 0;
    virtual void set_ice_role(IceRole role) = 0;
    
    virtual void set_ice_tiebreaker(uint64_t ice_tiebreaker) = 0;

    virtual void set_ice_credentials(const std::string& ice_ufrag,
            const std::string& ice_pwd);
    virtual void set_remote_ice_credentials(const std::string& ice_ufrag,
            const std::string& ice_pwd);    

    // The ufrag and pwd in |ice_params| must be set
    // before candidate gathering can start.
    virtual bool set_ice_parameters(const IceParameters& ice_params) = 0;
    virtual bool set_remote_ice_parameters(const IceParameters& ice_params) = 0;     
    
    virtual void set_remote_ice_mode(IceMode mode) = 0;
    
    virtual void set_ice_config(const IceConfig& config) = 0;
    
    virtual void set_ice_unique_ip(const std::string&) = 0;

    // Start gathering candidates if not already started, or if an ICE restart occurred. 
    virtual void start_gathering() = 0;

    virtual void add_remote_candidate(const Candidate& candidate) = 0;
    //virtual void remove_remote_candidate(const Candidate& candidate) = 0;    

    virtual IceGatheringState gathering_state() const = 0;

    // Returns the current stats for this connection.
    //virtual bool GetStats(ConnectionInfos* infos) = 0;

    // Returns RTT estimate over the currently active connection, or 0 if there is none.
    virtual int get_rtt_estimate() = 0; 
    
    rtcbase::Signal1<IceTransportChannel*> signal_gathering_state;

    // Handles sending and receiving of candidates.
    rtcbase::Signal2<IceTransportChannel*, const Candidate&>
        signal_candidate_gathered;

    rtcbase::Signal2<IceTransportChannel*, const Candidates&>
        signal_candidates_removed;
    
    rtcbase::Signal2<IceTransportChannel*, const Candidate&> signal_route_change;

    // Invoked when there is conflict in the ICE role between local and remote
    // agents.
    rtcbase::Signal1<IceTransportChannel*> signal_role_conflict;

    // Emitted whenever the transport state changed.
    rtcbase::Signal1<IceTransportChannel*> signal_state_changed;
    
    rtcbase::Signal4<IceTransportChannel*, CandidatePairInterface*, 
        int, bool> signal_selected_candidate_pair_changed;

    // Invoked when the transport is being destroyed.
    rtcbase::Signal1<IceTransportChannel*> signal_destroyed;       
};

} // namespace ice

#endif  //__ICE_ICE_TRANSPORT_CHANNEL_H_


