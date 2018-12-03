/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file peerconnection.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <assert.h>

#include <rtcbase/base64.h>
#include <rtcbase/string_encode.h>

#include "peerconnection.h"

extern bool g_is_connected;

namespace exam {

PeerConnection::PeerConnection(rtcbase::EventLoop* el, ice::PortAllocator* allocator) :
    _el(el), _allocator(allocator)
{
    assert(el);
    assert(allocator);

    _agent = new ice::IceAgent(_el, _allocator);
    _agent->signal_gathering_state.connect(this, &PeerConnection::on_gathering_state);
    _agent->signal_candidate_gathered.connect(this, &PeerConnection::on_candidate_gathered);
    _agent->signal_connection_state.connect(this, &PeerConnection::on_ice_connection_state);
    _agent->signal_read_packet.connect(this, &PeerConnection::on_read_packet);
}

PeerConnection::~PeerConnection() {
    if (_agent) {
        _agent->destroy();
        _agent = nullptr;
    }
}

void PeerConnection::on_gathering_state(ice::IceGatheringState new_state) {
    LOG(LS_TRACE) << "============GatheringState: " << new_state;
}

static const char k_line_type_attributes = 'a';
static const char k_attribute_candidate[] = "candidate";
static const char k_attribute_candidate_typ[] = "typ";
static const char k_attribute_candidate_raddr[] = "raddr";
static const char k_attribute_candidate_rport[] = "rport";
static const char k_attribute_candidate_ufrag[] = "ufrag";
static const char k_attribute_candidate_pwd[] = "pwd";
static const char k_attribute_candidate_generation[] = "generation";
static const char k_attribute_candidate_network_id[] = "network-id";
static const char k_attribute_candidate_network_cost[] = "network-cost";

static const char k_candidate_host[] = "host";
static const char k_candidate_srflx[] = "srflx";
static const char k_candidate_prflx[] = "prflx";
static const char k_candidate_relay[] = "relay";
static const char k_tcp_candidate_type[] = "tcptype";

static std::string sdp_serialize_candidate(const ice::Candidate& candidate) {
    // RFC 5245
    // a=candidate:<foundation> <component-id> <transport> <priority>
    // <connection-address> <port> typ <candidate-types>
    // [raddr <connection-address>] [rport <port>]
    // *(SP extension-att-name SP extension-att-value)
    std::string type;
    // Map the cricket candidate type to "host" / "srflx" / "prflx" / "relay"
    if (candidate.type() == ice::HOST_PORT_TYPE) {
        type = k_candidate_host;
    } else if (candidate.type() == ice::SRFLX_PORT_TYPE) {
        type = k_candidate_srflx;
    } else if (candidate.type() == ice::RELAY_PORT_TYPE) {
        type = k_candidate_relay;
    } else if (candidate.type() == ice::PRFLX_PORT_TYPE) {
        type = k_candidate_prflx;
        // Peer reflexive candidate may be signaled for being removed.
    } else {
        // Never write out candidates if we don't know the type.
        return "";
    }
    
    std::ostringstream os;
    os.str("");
    os << k_line_type_attributes << "=" << k_attribute_candidate; 

    os << ":" << candidate.foundation() << " " << candidate.component()
        << " " << candidate.protocol() << " " << candidate.priority() << " "
        << candidate.address().ipaddr().to_string() << " "
        << candidate.address().port_as_string() << " " << k_attribute_candidate_typ << " "
        << type << " ";

    // Related address
    if (!candidate.related_address().is_nil()) {
        os << k_attribute_candidate_raddr << " "
            << candidate.related_address().ipaddr().to_string() << " "
            << k_attribute_candidate_rport << " "
            << candidate.related_address().port_as_string() << " ";
    }

    if (candidate.protocol() == ice::TCP_PROTOCOL_NAME) {
        os << k_tcp_candidate_type << " " << candidate.tcptype() << " ";
    }

    // Extensions
    os << k_attribute_candidate_generation << " " << candidate.generation();
    if (!candidate.username().empty()) {
        os << " " << k_attribute_candidate_ufrag << " " << candidate.username();
    }
    if (candidate.network_id() > 0) {
        os << " " << k_attribute_candidate_network_id << " " << candidate.network_id();
    }
    if (candidate.network_cost() > 0) {
        os << " " << k_attribute_candidate_network_cost << " " << candidate.network_cost();
    }

    return os.str();
}

void PeerConnection::on_candidate_gathered(const std::string& transport_name, 
        const ice::Candidate& candidate)
{
    LOG(LS_NOTICE) << "===========New candidate, transport_name: " << transport_name
        << ", candidate: " << candidate.to_string();
    _candidates.push_back(candidate);
}

void PeerConnection::on_ice_connection_state(ice::IceConnectionState new_state) {
    LOG(LS_NOTICE) << "=============IceConnectionState: " << new_state;
    if (new_state == ice::k_ice_connection_connected || new_state == ice::k_ice_connection_completed) {
        g_is_connected = true;
    } else if (new_state == ice::k_ice_connection_failed) {
        g_is_connected = false;
    }
}

void PeerConnection::on_read_packet(const std::string& transport_name, int component, 
        const char* data, size_t len, const rtcbase::PacketTime& packet_time)
{
    (void)transport_name;
    (void)component;
    (void)packet_time;

    if (g_is_connected) {
        std::cout << "\rremote peer:" << std::string(data, len) << "\n->:" << std::flush;
    }
}

std::string PeerConnection::get_ice_sdp() {
    std::stringstream ss;
    
    ice::IceParameters params = _agent->get_ice_parameters();

    ss << "a=ice-ufrag:" << params.ufrag << "\n";
    ss << "a=ice-pwd:" << params.pwd << "\n"; 

    for (ice::Candidate c : _candidates) {
        ss << sdp_serialize_candidate(c) << "\n";
    }
    return ss.str();
}

template <class T>
static bool get_value_from_string(const std::string& s, T* t) {
	if (!rtcbase::from_string(s, t)) {
		return false;
	}
	return true;
}

static bool is_valid_port(int port) {
    return port >= 0 && port <= 65535;
}

static bool parse_candidate(const std::string& message,
		ice::Candidate* candidate,
		bool is_raw) 
{
	std::string attribute_candidate;
	std::string candidate_value;

	// |first_line| must be in the form of "candidate:<value>".
	if (!rtcbase::tokenize_first(message, ':', &attribute_candidate,
				&candidate_value) ||
			attribute_candidate != "a=candidate") 
    {
		if (is_raw) {
			std::ostringstream description;
			description << "Expect line: " << k_attribute_candidate << ":"
				<< "<candidate-str>";
            LOG(LS_WARNING) << description.str();
            return false;
		} else {
            return false;
		}
	}

	std::vector<std::string> fields;
	rtcbase::split(candidate_value, ' ', &fields);

	// RFC 5245
	// a=candidate:<foundation> <component-id> <transport> <priority>
	// <connection-address> <port> typ <candidate-types>
	// [raddr <connection-address>] [rport <port>]
	// *(SP extension-att-name SP extension-att-value)
	const size_t expected_min_fields = 8;
	if (fields.size() < expected_min_fields ||
			(fields[6] != k_attribute_candidate_typ)) 
    {
        return false;
	}
	const std::string& foundation = fields[0];

	int component_id = 0;
	if (!get_value_from_string(fields[1], &component_id)) {
		return false;
	}
	const std::string& transport = fields[2];
	uint32_t priority = 0;
	if (!get_value_from_string(fields[3], &priority)) {
		return false;
	}
	const std::string& connection_address = fields[4];
	int port = 0;
	if (!get_value_from_string(fields[5], &port)) {
		return false;
	}
	if (!is_valid_port(port)) {
        return false;
	}
    rtcbase::SocketAddress address(connection_address, port);

	ice::ProtocolType protocol;
	if (!ice::string_to_proto(transport.c_str(), &protocol)) {
		return false;
	}
	switch (protocol) {
        case ice::PROTO_UDP:
		case ice::PROTO_TCP:
		case ice::PROTO_SSLTCP:
			// Supported protocol.
			break;
		default:
			return false;
	}

	std::string candidate_type;
	const std::string& type = fields[7];
	if (type == k_candidate_host) {
		candidate_type = ice::HOST_PORT_TYPE;
	} else if (type == k_candidate_srflx) {
		candidate_type = ice::SRFLX_PORT_TYPE;
	} else if (type == k_candidate_relay) {
		candidate_type = ice::RELAY_PORT_TYPE;
	} else if (type == k_candidate_prflx) {
		candidate_type = ice::PRFLX_PORT_TYPE;
	} else {
		return false;
	}

	size_t current_position = expected_min_fields;
    rtcbase::SocketAddress related_address;
	// The 2 optional fields for related address
	// [raddr <connection-address>] [rport <port>]
	if (fields.size() >= (current_position + 2) &&
			fields[current_position] == k_attribute_candidate_raddr) {
		related_address.set_IP(fields[++current_position]);
		++current_position;
	}
	if (fields.size() >= (current_position + 2) &&
			fields[current_position] == k_attribute_candidate_rport) 
    {
		int port = 0;
		if (!get_value_from_string(fields[++current_position], &port)) {
			return false;
		}
		if (!is_valid_port(port)) {
			return false;
		}
		related_address.set_port(port);
		++current_position;
	}

	// If this is a TCP candidate, it has additional extension as defined in
	// RFC 6544.
	std::string tcptype;
	if (fields.size() >= (current_position + 2) &&
			fields[current_position] == k_tcp_candidate_type) {
		tcptype = fields[++current_position];
		++current_position;

		if (tcptype != ice::TCPTYPE_ACTIVE_STR &&
				tcptype != ice::TCPTYPE_PASSIVE_STR &&
				tcptype != ice::TCPTYPE_SIMOPEN_STR) 
        {
            return false;
		}

		if (protocol != ice::PROTO_TCP) {
            return false;
		}
	}

	// Extension
	// Though non-standard, we support the ICE ufrag and pwd being signaled on
	// the candidate to avoid issues with confusing which generation a candidate
	// belongs to when trickling multiple generations at the same time.
	std::string username;
	std::string password;
	uint32_t generation = 0;
	uint16_t network_id = 0;
	uint16_t network_cost = 0;
	for (size_t i = current_position; i + 1 < fields.size(); ++i) {
		// RFC 5245
		// *(SP extension-att-name SP extension-att-value)
		if (fields[i] == k_attribute_candidate_generation) {
			if (!get_value_from_string(fields[++i], &generation)) {
				return false;
			}
		} else if (fields[i] == k_attribute_candidate_ufrag) {
			username = fields[++i];
		} else if (fields[i] == k_attribute_candidate_pwd) {
			password = fields[++i];
		} else if (fields[i] == k_attribute_candidate_network_id) {
			if (!get_value_from_string(fields[++i], &network_id)) {
				return false;
			}
		} else if (fields[i] == k_attribute_candidate_network_cost) {
			if (!get_value_from_string(fields[++i], &network_cost)) {
				return false;
			}
			network_cost = std::min(network_cost, rtcbase::k_network_cost_max);
		} else {
			// Skip the unknown extension.
			++i;
		}
	}

	*candidate = ice::Candidate(component_id, ice::proto_to_string(protocol),
			address, priority, username, password, candidate_type,
			generation, foundation, network_id, network_cost);
	candidate->set_related_address(related_address);
	candidate->set_tcptype(tcptype);
	return true;
}

void PeerConnection::set_remote_ice(const std::string& ice_sdp) {
    std::vector<std::string> lines;
    ice::IceParameters ice_params; 
    ice::Candidates candidates;
    rtcbase::split(rtcbase::Base64::decode(ice_sdp, rtcbase::Base64::DO_LAX), '\n', &lines);
    for (std::string line : lines) {
        if (line == "") {
            continue;
        }
        
        if (strstr(line.c_str(), "a=ice-ufrag")) {
            std::vector<std::string> fields;
            rtcbase::split(line, ':', &fields);
            if (fields.size() == 2) {
                ice_params.ufrag = fields[1];
            }
        } else if (strstr(line.c_str(), "a=ice-pwd")) {
            std::vector<std::string> fields;
            rtcbase::split(line, ':', &fields);
            if (fields.size() == 2) {
                ice_params.pwd = fields[1];
            }
        } else if (strstr(line.c_str(), "a=candidate")) {
            ice::Candidate candidate;
            parse_candidate(line, &candidate, true); 
            candidates.push_back(candidate);
            break;
        }
    }
    _agent->set_remote_ice_parameters(ice_params);
    _agent->add_remote_candidates("audio", candidates, NULL);
}

int PeerConnection::send_data(const char* data, size_t len) {
    return _agent->send_packet("audio", 1, data, len);
}

} // namespace exam


