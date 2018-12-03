/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file candidate.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_CANDIDATE_H_
#define  __ICE_CANDIDATE_H_

#include <limits.h>
#include <math.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>

#include <rtcbase/basic_types.h>
#include <rtcbase/random.h>
#include <rtcbase/network.h>
#include <rtcbase/socket_address.h>

#include "ice_common.h"

namespace ice {

class Candidate {
public:
    Candidate();
    // TODO: Match the ordering and param list as per RFC 5245
    // candidate-attribute syntax. http://tools.ietf.org/html/rfc5245#section-15.1 
    Candidate(int component,
            const std::string& protocol,
            const rtcbase::SocketAddress& address,
            uint32_t priority,
            const std::string& username,
            const std::string& password,
            const std::string& type,
            uint32_t generation,
            const std::string& foundation,
            uint16_t network_id = 0,
            uint16_t network_cost = 0);
    Candidate(const Candidate&);
    ~Candidate();

    const std::string & id() const { return _id; }
    void set_id(const std::string & id) { _id = id; }

    int component() const { return _component; }
    void set_component(int component) { _component = component; }

    const std::string & protocol() const { return _protocol; }
    void set_protocol(const std::string & protocol) { _protocol = protocol; }

    // The protocol used to talk to relay.
    const std::string& relay_protocol() const { return _relay_protocol; }
    void set_relay_protocol(const std::string& protocol) {
        _relay_protocol = protocol;
    }

    const rtcbase::SocketAddress & address() const { return _address; }
    void set_address(const rtcbase::SocketAddress & address) {
        _address = address;
    } 

    uint32_t priority() const { return _priority; }
    void set_priority(const uint32_t priority) { _priority = priority; }
    
    const std::string & username() const { return _username; }
    void set_username(const std::string & username) { _username = username; }

    const std::string & password() const { return _password; }
    void set_password(const std::string & password) { _password = password; } 

    const std::string & type() const { return _type; }
    void set_type(const std::string & type) { _type = type; }
    
    const std::string & network_name() const { return _network_name; }
    void set_network_name(const std::string & network_name) {
        _network_name = network_name;
    }

    rtcbase::AdapterType network_type() const { return _network_type; }
    void set_network_type(rtcbase::AdapterType network_type) {
        _network_type = network_type;
    }
    
    // Candidates in a new generation replace those in the old generation.
    uint32_t generation() const { return _generation; }
    void set_generation(uint32_t generation) { _generation = generation; }
    const std::string generation_str() const {
        std::ostringstream ost;
        ost << _generation;
        return ost.str();
    }
    void set_generation_str(const std::string& str) {
        std::istringstream ist(str);
        ist >> _generation;
    }
    
    // |network_cost| measures the cost/penalty of using this candidate. A network
    // cost of 0 indicates this candidate can be used freely. A value of
    // rtc::kNetworkCostMax indicates it should be used only as the last resort.
    void set_network_cost(uint16_t network_cost) {
        if (network_cost > rtcbase::k_network_cost_max) {
            return;
        }
        _network_cost = network_cost;
    }
    uint16_t network_cost() const { return _network_cost; }
    
    // An ID assigned to the network hosting the candidate.
    uint16_t network_id() const { return _network_id; }
    void set_network_id(uint16_t network_id) { _network_id = network_id; } 

    const std::string& foundation() const {
        return _foundation;
    }

    void set_foundation(const std::string& foundation) {
        _foundation = foundation;
    }

    const rtcbase::SocketAddress& related_address() const {
        return _related_address;
    }
    void set_related_address(
            const rtcbase::SocketAddress& related_address) {
        _related_address = related_address;
    }
    
    const std::string& tcptype() const { return _tcptype; }
    void set_tcptype(const std::string& tcptype) {
        _tcptype = tcptype;
    }
    
    // The name of the transport channel of this candidate.
    const std::string& transport_name() const { return _transport_name; }
    void set_transport_name(const std::string& transport_name) {
        _transport_name = transport_name;
    }

    // Determines whether this candidate is equivalent to the given one.
    bool is_equivalent(const Candidate& c) const;

    // Determines whether this candidate can be considered equivalent to the
    // given one when looking for a matching candidate to remove.
    bool matches_for_removal(const Candidate& c) const; 

    std::string to_string() const {
        return to_string_internal(false);
    }

    std::string to_sensitive_string() const {
        return to_string_internal(true);
    }

    uint32_t get_priority(uint32_t type_preference,
            int network_adapter_preference,
            int relay_preference) const;
    
    bool operator==(const Candidate& o) const;
    bool operator!=(const Candidate& o) const;

private:
    std::string to_string_internal(bool sensitive) const; 
    
private:
    std::string _id;
    int _component;
    std::string _protocol;
    std::string _relay_protocol;
    rtcbase::SocketAddress _address;
    uint32_t _priority;
    std::string _username;
    std::string _password;
    std::string _type;
    std::string _network_name;
    rtcbase::AdapterType _network_type;
    uint32_t _generation;
    std::string _foundation;
    rtcbase::SocketAddress _related_address;
    std::string _tcptype;
    std::string _transport_name;
    uint16_t _network_id;
    uint16_t _network_cost;  
};

typedef std::vector<Candidate> Candidates;

} // namespace ice

#endif  //__ICE_CANDIDATE_H_


