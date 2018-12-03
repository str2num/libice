/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file common.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_ICE_COMMON_H_
#define  __ICE_ICE_COMMON_H_

#include <rtcbase/logging.h>

// Common log description format for ice messages
#define LOG_J(sev, obj) LOG(sev) << "ICE:" << obj->to_string() << ": "
#define LOG_JV(sev, obj) LOG_V(sev) << "ICE:" << obj->to_string() << ": "

namespace ice {

// Minimum ufrag length is 4 characters as per RFC5245.
const int ICE_UFRAG_LENGTH = 4;
// Minimum password length of 22 characters as per RFC5245. We chose 24 because
// some internal systems expect password to be multiple of 4.
const int ICE_PWD_LENGTH = 24;
const size_t ICE_UFRAG_MIN_LENGTH = 4;
const size_t ICE_PWD_MIN_LENGTH = 22;
const size_t ICE_UFRAG_MAX_LENGTH = 256;
const size_t ICE_PWD_MAX_LENGTH = 256;

const int ICE_CANDIDATE_COMPONENT_RTP = 1;
const int ICE_CANDIDATE_COMPONENT_RTCP = 2;
const int ICE_CANDIDATE_COMPONENT_DEFAULT = 1;

const int MIN_CHECK_RECEIVING_INTERVAL = 50;  // ms
const int RECEIVING_SWITCHING_DELAY = 1000;  // ms
const int BACKUP_CONNECTION_PING_INTERVAL = 25 * 1000;
const int REGATHER_ON_FAILED_NETWORKS_INTERVAL = 5 * 60 * 1000;

// When the socket is unwritable, we will use 10 Kbps (ignoring IP+UDP headers)
// for pinging.  When the socket is writable, we will use only 1 Kbps because
// we don't want to degrade the quality on a modem.  These numbers should work
// well on a 28.8K modem, which is the slowest connection on which the voice
// quality is reasonable at all.
const int STUN_PING_PACKET_SIZE = 60 * 8;
const int STRONG_PING_INTERVAL = 1000 * STUN_PING_PACKET_SIZE / 1000;
const int WEAK_PING_INTERVAL = 1000 * STUN_PING_PACKET_SIZE / 10000;
const int WEAK_OR_STABILIZING_WRITABLE_CONNECTION_PING_INTERVAL = 900;  // ms
const int STRONG_AND_STABLE_WRITABLE_CONNECTION_PING_INTERVAL = 2500;  // ms
const int CONNECTION_WRITE_CONNECT_TIMEOUT = 5 * 1000;  // 5 seconds
const uint32_t CONNECTION_WRITE_CONNECT_FAILURES = 5;  // 5 pings

const int MIN_CONNECTION_LIFETIME = 10 * 1000;  // 10 seconds.
const int DEAD_CONNECTION_RECEIVE_TIMEOUT = 30 * 1000;  // 30 seconds.
const int WEAK_CONNECTION_RECEIVE_TIMEOUT = 3000;  // 3 seconds
const int CONNECTION_WRITE_TIMEOUT = 15 * 1000;  // 15 seconds
// There is no harm to keep this value high other than a small amount
// of increased memory, but in some networks (2G), we observe up to 60s RTTs.
const int CONNECTION_RESPONSE_TIMEOUT = 60 * 1000;  // 60 seconds

// Whether our side of the call is driving the negotiation, or the other side.
enum IceRole {
    ICEROLE_CONTROLLING = 0,
    ICEROLE_CONTROLLED,
    ICEROLE_UNKNOWN
};

// ICE RFC 5245 implementation type.
enum IceMode {
    ICEMODE_FULL,  // As defined in http://tools.ietf.org/html/rfc5245#section-4.1
    ICEMODE_LITE   // As defined in http://tools.ietf.org/html/rfc5245#section-4.2
};

struct IceParameters {
    // TODO(honghaiz): Include ICE mode in this structure to match the ORTC
    // struct:
    // http://ortc.org/wp-content/uploads/2016/03/ortc.html#idl-def-RTCIceParameters
    std::string ufrag;
    std::string pwd;
    bool renomination = false;
    IceParameters() = default;
    IceParameters(const std::string& ice_ufrag,
            const std::string& ice_pwd,
            bool ice_renomination)
        : ufrag(ice_ufrag), pwd(ice_pwd), renomination(ice_renomination) {}

    bool operator==(const IceParameters& other) {
        return ufrag == other.ufrag && pwd == other.pwd &&
            renomination == other.renomination;
    }
    bool operator!=(const IceParameters& other) { return !(*this == other); }
};

constexpr auto* ICE_OPTION_TRICKLE = "trickle";
constexpr auto* ICE_OPTION_RENOMINATION = "renomination";

const char* get_ice_role_str(IceRole role);

} // namespace ice

#endif  //__ICE_ICE_COMMON_H_


