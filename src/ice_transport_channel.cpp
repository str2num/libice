/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file ice_transport_channel.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include "ice_transport_channel.h"

namespace ice {

const char* get_ice_gathering_state_str(IceGatheringState state) {
    switch (state) {
        case k_ice_gathering_new:
            return "new";
        case k_ice_gathering_gathering:
            return "gathering";
        case k_ice_gathering_complete:
            return "complete";
        default:
            return "unknown";
    }
}

IceTransportChannel::IceTransportChannel() = default;

IceTransportChannel::~IceTransportChannel() = default;

void IceTransportChannel::set_ice_credentials(const std::string& ice_ufrag,
        const std::string& ice_pwd) 
{
    set_ice_parameters(IceParameters(ice_ufrag, ice_pwd, false));
}

void IceTransportChannel::set_remote_ice_credentials(const std::string& ice_ufrag,
        const std::string& ice_pwd) 
{
    set_remote_ice_parameters(IceParameters(ice_ufrag, ice_pwd, false));
}

} // namespace ice


