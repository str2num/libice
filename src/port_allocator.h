/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port_allocator.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_PORT_ALLOCATOR_H_
#define  __ICE_PORT_ALLOCATOR_H_

#include <deque>
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>

#include <rtcbase/log_trace_id.h>
#include <rtcbase/sigslot.h>
#include "port.h"

namespace ice {

enum {
    // Disable local UDP ports. This doesn't impact how we connect to relay
    // servers.
    PORTALLOCATOR_DISABLE_UDP = 0x01,
    PORTALLOCATOR_DISABLE_STUN = 0x02,
    PORTALLOCATOR_DISABLE_RELAY = 0x04,
    // Disable local TCP ports. This doesn't impact how we connect to relay
    // servers.
    PORTALLOCATOR_DISABLE_TCP = 0x08,
    PORTALLOCATOR_ENABLE_IPV6 = 0x40,
    // TODO(pthatcher): Remove this once it's no longer used in:
    // remoting/client/plugin/pepper_port_allocator.cc
    // remoting/protocol/chromium_port_allocator.cc
    // remoting/test/fake_port_allocator.cc
    // It's a no-op and is no longer needed.
    PORTALLOCATOR_ENABLE_SHARED_UFRAG = 0x80,
    PORTALLOCATOR_ENABLE_SHARED_SOCKET = 0x100,
    PORTALLOCATOR_ENABLE_STUN_RETRANSMIT_ATTRIBUTE = 0x200,
    // When specified, we'll only allocate the STUN candidate for the public
    // interface as seen by regular http traffic and the HOST candidate associated
    // with the default local interface.
    PORTALLOCATOR_DISABLE_ADAPTER_ENUMERATION = 0x400,
    // When specified along with PORTALLOCATOR_DISABLE_ADAPTER_ENUMERATION, the
    // default local candidate mentioned above will not be allocated. Only the
    // STUN candidate will be.
    PORTALLOCATOR_DISABLE_DEFAULT_LOCAL_CANDIDATE = 0x800,
    // Disallow use of UDP when connecting to a relay server. Since proxy servers
    // usually don't handle UDP, using UDP will leak the IP address.
    PORTALLOCATOR_DISABLE_UDP_RELAY = 0x1000,

    // When multiple networks exist, do not gather candidates on the ones with
    // high cost. So if both Wi-Fi and cellular networks exist, gather only on the
    // Wi-Fi network. If a network type is "unknown", it has a cost lower than
    // cellular but higher than Wi-Fi/Ethernet. So if an unknown network exists,
    // cellular networks will not be used to gather candidates and if a Wi-Fi
    // network is present, "unknown" networks will not be usd to gather
    // candidates. Doing so ensures that even if a cellular network type was not
    // detected initially, it would not be used if a Wi-Fi network is present.
    PORTALLOCATOR_DISABLE_COSTLY_NETWORKS = 0x2000,
};

const uint32_t k_default_port_allocator_flags = 0;
const uint32_t k_default_step_delay = 1000;  // 1 sec step delay.

// CF = CANDIDATE FILTER
enum {
    CF_NONE = 0x0,
    CF_HOST = 0x1,
    CF_REFLEXIVE = 0x2,
    CF_RELAY = 0x4,
    CF_ALL = 0x7,
};

class PortAllocatorSession : public rtcbase::HasSlots<>, public rtcbase::LogTraceId {
public:
    // Content name passed in mostly for logging and debugging.
    PortAllocatorSession(const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd,
            uint32_t flags,
            const std::string& ice_unique_ip);

    // Subclasses should clean up any ports created.
    virtual ~PortAllocatorSession() {}
    
    uint32_t flags() const { return _flags; }
    void set_flags(uint32_t flags) { _flags = flags; }
    std::string content_name() const { return _content_name; }
    int component() const { return _component; }
    const std::string& ice_ufrag() const { return _ice_ufrag; }
    const std::string& ice_pwd() const { return _ice_pwd; }
    const std::string& ice_unique_ip() const { return _ice_unique_ip; }
    bool pooled() const { return _ice_ufrag.empty(); }

    // Starts gathering STUN and Relay configurations.
    virtual void start_getting_ports() = 0;
    
    // Whether the session has completely stopped.
    virtual bool is_stopped() const { return false; }
    
    virtual bool candidates_allocation_done() const = 0;
    
    rtcbase::Signal2<PortAllocatorSession*, PortInterface*> signal_port_ready;
    rtcbase::Signal2<PortAllocatorSession*,
        const std::vector<Candidate>&> signal_candidates_ready;
    rtcbase::Signal1<PortAllocatorSession*> signal_candidates_allocation_done;

    virtual uint32_t generation() { return _generation; }
    virtual void set_generation(uint32_t generation) { _generation = generation; }
    
    std::string to_string();

protected:
    // This method is called when a pooled session (which doesn't have these
    // properties initially) is returned by PortAllocator::TakePooledSession,
    // and the content name, component, and ICE ufrag/pwd are updated.
    //
    // A subclass may need to override this method to perform additional actions,
    // such as applying the updated information to ports and candidates.
    virtual void update_ice_parameters_internal() {} 

private:
    void set_ice_parameters(const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd) 
    {
        _content_name = content_name;
        _component = component;
        _ice_ufrag = ice_ufrag;
        _ice_pwd = ice_pwd;
        update_ice_parameters_internal();
    }

private:
    uint32_t _flags;
    uint32_t _generation;
    std::string _content_name;
    int _component;
    std::string _ice_ufrag;
    std::string _ice_pwd;
    std::string _ice_unique_ip;

    // SetIceParameters is an implementation detail which only PortAllocator
    // should be able to call.
    friend class PortAllocator;
};

class PortAllocator : public rtcbase::HasSlots<> {
public:
    PortAllocator() :
        _flags(k_default_port_allocator_flags),
        _min_port(0),
        _max_port(0),
        _step_delay(k_default_step_delay),
        _candidate_filter(CF_ALL) {}
    virtual ~PortAllocator() {}
    
    // This should be called on the PortAllocator's thread before the
    // PortAllocator is used. Subclasses may override this if necessary.
    virtual void initialize() {} 

    const ServerAddresses& stun_servers() const { return _stun_servers; }
    
    // Sets the network types to ignore.
    // Values are defined by the AdapterType enum.
    // For instance, calling this with
    // ADAPTER_TYPE_ETHERNET | ADAPTER_TYPE_LOOPBACK will ignore Ethernet and
    // loopback interfaces.
    virtual void set_network_ignore_mask(int network_ignore_mask) = 0;

    std::unique_ptr<PortAllocatorSession> create_session(
            const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd,
            const std::string& ice_unique_ip);

    uint32_t flags() const { return _flags; }
    void set_flags(uint32_t flags) { _flags = flags; }
    
    int min_port() const { return _min_port; }
    int max_port() const { return _max_port; }

    bool prune_turn_ports() const { return _prune_turn_ports; }
    
    // Gets/Sets the Origin value used for WebRTC STUN requests.
    const std::string& origin() const { return _origin; }
    void set_origin(const std::string& origin) { _origin = origin; } 
    
protected:
    virtual PortAllocatorSession* create_session_internal(
            const std::string& content_name,
            int component,
            const std::string& ice_ufrag,
            const std::string& ice_pwd,
            const std::string& ice_unique_ip) = 0;

protected:
    uint32_t _flags;
    int _min_port;
    int _max_port;
    uint32_t _step_delay;
    uint32_t _candidate_filter;
    std::string _origin;

private:
    ServerAddresses _stun_servers;
    bool _prune_turn_ports = false;
};

} // namespace ice

#endif  //__ICE_PORT_ALLOCATOR_H_


