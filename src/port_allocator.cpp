/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port_allocator.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include "port_allocator.h"

namespace ice {

PortAllocatorSession::PortAllocatorSession(const std::string& content_name,
        int component,
        const std::string& ice_ufrag,
        const std::string& ice_pwd,
        uint32_t flags,
        const std::string& ice_unique_ip)
    : _flags(flags),
    _generation(0),
    _content_name(content_name),
    _component(component),
    _ice_ufrag(ice_ufrag),
    _ice_pwd(ice_pwd),
    _ice_unique_ip(ice_unique_ip)
{
}

std::string PortAllocatorSession::to_string() {
    std::stringstream ss;
    ss << "PortAllocatorSession[trace_id=" << get_log_trace_id()
       << "]";
    return ss.str();
}

std::unique_ptr<PortAllocatorSession> PortAllocator::create_session(
        const std::string& content_name,
        int component,
        const std::string& ice_ufrag,
        const std::string& ice_pwd,
        const std::string& ice_unique_ip) 
{
    auto session = std::unique_ptr<PortAllocatorSession>(
            create_session_internal(content_name, component, 
                ice_ufrag, ice_pwd, ice_unique_ip));
    return session;
}

} // namespace ice


