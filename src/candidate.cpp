/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file candidate.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include "candidate.h"

namespace ice {

Candidate::Candidate()
    : _id(rtcbase::create_random_string(8)),
    _component(0),
    _priority(0),
    _network_type(rtcbase::ADAPTER_TYPE_UNKNOWN),
    _generation(0),
    _network_id(0),
    _network_cost(0) {}

Candidate::Candidate(int component,
        const std::string& protocol,
        const rtcbase::SocketAddress& address,
        uint32_t priority,
        const std::string& username,
        const std::string& password,
        const std::string& type,
        uint32_t generation,
        const std::string& foundation,
        uint16_t network_id,
        uint16_t network_cost)
    : _id(rtcbase::create_random_string(8)),
    _component(component),
    _protocol(protocol),
    _address(address),
    _priority(priority),
    _username(username),
    _password(password),
    _type(type),
    _network_type(rtcbase::ADAPTER_TYPE_UNKNOWN),
    _generation(generation),
    _foundation(foundation),
    _network_id(network_id),
    _network_cost(network_cost) {}

Candidate::Candidate(const Candidate&) = default;

Candidate::~Candidate() = default;

// Determines whether this candidate is equivalent to the given one.
bool Candidate::is_equivalent(const Candidate& c) const {
    // We ignore the network name, since that is just debug information, and
    // the priority and the network cost, since they should be the same if the
    // rest are.
    return (_component == c._component) && (_protocol == c._protocol) &&
        (_address == c._address) && (_username == c._username) &&
        (_password == c._password) && (_type == c._type) &&
        (_generation == c._generation) && (_foundation == c._foundation) &&
        (_related_address == c._related_address) &&
        (_network_id == c._network_id);
}

bool Candidate::matches_for_removal(const Candidate& c) const {
    return _component == c._component && _protocol == c._protocol &&
        _address == c._address;
} 

std::string Candidate::to_string_internal(bool sensitive) const {
    std::ostringstream ost;
    std::string address = sensitive ? _address.to_sensitive_string() :
        _address.to_string();
    ost << "Cand[transport_name=" << _transport_name 
        << " foundation=" << _foundation 
        << " component=" << _component
        << " protocol=" << _protocol 
        << " priority=" << _priority 
        << " address=" << address 
        << " type=" << _type 
        << " related_address=" << _related_address 
        << " ice_ufrag=" << _username 
        << " ice_pwd=" << _password 
        << " network_id=" << _network_id 
        << " network_cost=" << _network_cost 
        << " generation=" << _generation 
        << "]";
    return ost.str();
}

uint32_t Candidate::get_priority(uint32_t type_preference,
        int network_adapter_preference,
        int relay_preference) const 
{
    // RFC 5245 - 4.1.2.1.
    // priority = (2^24)*(type preference) +
    //            (2^8)*(local preference) +
    //            (2^0)*(256 - component ID)

    // |local_preference| length is 2 bytes, 0-65535 inclusive.
    // In our implemenation we will partion local_preference into
    //              0                 1
    //       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |  NIC Pref     |    Addr Pref  |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // NIC Type - Type of the network adapter e.g. 3G/Wifi/Wired.
    // Addr Pref - Address preference value as per RFC 3484.
    // local preference =  (NIC Type << 8 | Addr_Pref) - relay preference.

    int addr_pref = IP_address_precedence(_address.ipaddr());
    int local_preference = ((network_adapter_preference << 8) | addr_pref) +
        relay_preference;

    return (type_preference << 24) |
        (local_preference << 8) |
        (256 - _component);
}

bool Candidate::operator==(const Candidate& o) const {
    return _id == o._id && _component == o._component &&
        _protocol == o._protocol && _relay_protocol == o._relay_protocol &&
        _address == o._address && _priority == o._priority &&
        _username == o._username && _password == o._password &&
        _type == o._type && _network_name == o._network_name &&
        _network_type == o._network_type && _generation == o._generation &&
        _foundation == o._foundation &&
        _related_address == o._related_address && _tcptype == o._tcptype &&
        _transport_name == o._transport_name && _network_id == o._network_id;
}

bool Candidate::operator!=(const Candidate& o) const {
    return !(*this == o);
}

} // namespace ice


