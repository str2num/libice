/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <algorithm>
#include <vector>
#include <memory>
#include <unistd.h>

#include <rtcbase/ptr_utils.h>
#include <rtcbase/crc32.h>
#include <rtcbase/random.h>
#include <rtcbase/logging.h>
#include <rtcbase/network.h>
#include <rtcbase/string_encode.h>

#include "ice_common.h"
#include "port_allocator.h"
#include "port.h"

namespace {

// Determines whether we have seen at least the given maximum number of
// pings fail to have a response.
inline bool too_many_failures(
        const std::vector<ice::Connection::SentPing>& pings_since_last_response,
        uint32_t maximum_failures,
        int rtt_estimate,
        int64_t now) 
{
    // If we haven't sent that many pings, then we can't have failed that many.
    if (pings_since_last_response.size() < maximum_failures) {
        return false;
    }

    // Check if the window in which we would expect a response to the ping has
    // already elapsed.
    int64_t expected_response_time =
        pings_since_last_response[maximum_failures - 1].sent_time + rtt_estimate;
    return now > expected_response_time;
}

// Determines whether we have gone too long without seeing any response.
inline bool too_long_without_response(
        const std::vector<ice::Connection::SentPing>& pings_since_last_response,
        int64_t maximum_time,
        int64_t now) 
{
    if (pings_since_last_response.size() == 0) {
        return false;
    }

    auto first = pings_since_last_response[0];
    return now > (first.sent_time + maximum_time);
}

// We will restrict RTT estimates (when used for determining state) to be
// within a reasonable range.
const int MINIMUM_RTT = 100;   // 0.1 seconds
const int MAXIMUM_RTT = 60000; // 60 seconds

// When we don't have any RTT data, we have to pick something reasonable.  We
// use a large value just in case the connection is really slow.
const int DEFAULT_RTT = 3000; // 3 seconds

// Computes our estimate of the RTT given the current estimate.
inline int conservative_RTT_estimate(int rtt) {
    return std::max(MINIMUM_RTT, std::min(MAXIMUM_RTT, 2 * rtt));
}

// Weighting of the old rtt value to new data.
const int RTT_RATIO = 3;  // 3 : 1

} // namespace

namespace ice {

const char HOST_PORT_TYPE[] = "host";
const char SRFLX_PORT_TYPE[] = "srflx";
const char PRFLX_PORT_TYPE[] = "prflx";
const char RELAY_PORT_TYPE[] = "relay";

const char UDP_PROTOCOL_NAME[] = "udp";
const char TCP_PROTOCOL_NAME[] = "tcp";
const char SSLTCP_PROTOCOL_NAME[] = "ssltcp";

static const char* const PROTO_NAMES[] = { UDP_PROTOCOL_NAME,
    TCP_PROTOCOL_NAME,
    SSLTCP_PROTOCOL_NAME };

const char* proto_to_string(ProtocolType proto) {
    return PROTO_NAMES[proto];
}

bool string_to_proto(const char* value, ProtocolType* proto) {
    for (size_t i = 0; i <= PROTO_LAST; ++i) {
        if (strcasecmp(PROTO_NAMES[i], value) == 0) {
            *proto = static_cast<ProtocolType>(i);
            return true;
        }
    }
    return false;
}

// RFC 6544, TCP candidate encoding rules.
const int DISCARD_PORT = 9;
const char TCPTYPE_ACTIVE_STR[] = "active";
const char TCPTYPE_PASSIVE_STR[] = "passive";
const char TCPTYPE_SIMOPEN_STR[] = "so";

// Foundation:  An arbitrary string that is the same for two candidates
//   that have the same type, base IP address, protocol (UDP, TCP,
//   etc.), and STUN or TURN server.  If any of these are different,
//   then the foundation will be different.  Two candidate pairs with
//   the same foundation pairs are likely to have similar network
//   characteristics.  Foundations are used in the frozen algorithm.
static std::string compute_foundation(const std::string& type,
        const std::string& protocol,
        const std::string& relay_protocol,
        const rtcbase::SocketAddress& base_address) 
{
    std::ostringstream ost;
    ost << type << base_address.ipaddr().to_string() << protocol << relay_protocol;
    return rtcbase::to_string<uint32_t>(rtcbase::compute_crc32(ost.str()));
}

Port::Port(const std::string& type,
        PacketSocketFactory* factory,
        rtcbase::Network* network,
        const rtcbase::IPAddress& ip,
        const std::string& username_fragment,
        const std::string& password)
    : rtcbase::MemCheck("Port"),
    _factory(factory),
    _type(type),
    _network(network),
    _ip(ip),
    _min_port(0),
    _max_port(0),
    _component(ICE_CANDIDATE_COMPONENT_DEFAULT),
    _generation(0),
    _ice_username_fragment(username_fragment),
    _password(password),
    _enable_port_packets(false),
    _ice_role(ICEROLE_UNKNOWN),
    _tiebreaker(0),
    _shared_socket(true) 
{
    construct();
}

Port::Port(const std::string& type,
           PacketSocketFactory* factory,
           rtcbase::Network* network,
           const rtcbase::IPAddress& ip,
           uint16_t min_port,
           uint16_t max_port,
           const std::string& username_fragment,
           const std::string& password)
    : rtcbase::MemCheck("Port"),
      _factory(factory),
      _type(type),
      _network(network),
      _ip(ip),
      _min_port(min_port),
      _max_port(max_port),
      _component(ICE_CANDIDATE_COMPONENT_DEFAULT),
      _generation(0),
      _ice_username_fragment(username_fragment),
      _password(password),
      _enable_port_packets(false),
      _ice_role(ICEROLE_UNKNOWN),
      _tiebreaker(0),
      _shared_socket(false) 
{
    construct();
}

void Port::construct() {
    _network_cost = _network->get_cost();
    LOG_J(LS_TRACE, this) << "Port created with network cost " << _network_cost;
}

Port::~Port() {
    // Delete all of the remaining connections.  We copy the list up front
    // because each deletion will cause it to be modified.
    std::vector<Connection*> list;

    AddressMap::iterator iter = _connections.begin();
    while (iter != _connections.end()) {
        list.push_back(iter->second);
        ++iter;
    }

    for (uint32_t i = 0; i < list.size(); i++) {
        delete list[i];
    }
}

void Port::on_connection_destroyed(Connection* conn) {
    AddressMap::iterator iter =
        _connections.find(conn->remote_candidate().address());
    if (iter == _connections.end()) {
        return;
    }
    _connections.erase(iter);
    handle_connection_destroyed(conn);

    // Ports time out after all connections fail if it is not marked as
    // "keep alive until pruned."
    // Note: If a new connection is added after this message is posted, but it
    // fails and is removed before kPortTimeoutDelay, then this message will
    // not cause the Port to be destroyed.
    if (_connections.empty()) {
        /*
        last_time_all_connections_removed_ = rtc::TimeMillis();
        thread_->PostDelayed(RTC_FROM_HERE, timeout_delay_, this,
                MSG_DESTROY_IF_DEAD);
        */
    }
}

void Port::keep_alive_until_pruned() {
    // If it is pruned, we won't bring it up again.
    if (_state == State::INIT) {
        _state = State::KEEP_ALIVE_UNTIL_PRUNED;
    }
}

Connection* Port::get_connection(const rtcbase::SocketAddress& remote_addr) {
    AddressMap::const_iterator iter = _connections.find(remote_addr);
    if (iter != _connections.end()) {
        return iter->second;
    } else {
        return NULL;
    }
}

void Port::send_binding_response(StunMessage* request,
        const rtcbase::SocketAddress& addr) 
{
    if (request->type() != STUN_BINDING_REQUEST) {
        return;
    }
    
    // Retrieve the username from the request.
    const StunByteStringAttribute* username_attr =
        request->get_byte_string(STUN_ATTR_USERNAME);
    if (username_attr == NULL) {
        // No valid username, skip the response.
        return;
    }

    // Fill in the response message.
    StunMessage response;
    response.set_type(STUN_BINDING_RESPONSE);
    response.set_transaction_ID(request->transaction_id());
    const StunUInt32Attribute* retransmit_attr =
        request->get_uint32(STUN_ATTR_RETRANSMIT_COUNT);
    if (retransmit_attr) {
        // Inherit the incoming retransmit value in the response so the other side
        // can see our view of lost pings.
        response.add_attribute(rtcbase::make_unique<StunUInt32Attribute>(
                    STUN_ATTR_RETRANSMIT_COUNT, retransmit_attr->value()));

        if (retransmit_attr->value() > CONNECTION_WRITE_CONNECT_FAILURES) {
            LOG_J(LS_TRACE, this)
                << "Received a remote ping with high retransmit count: "
                << retransmit_attr->value();
        }
    }

    response.add_attribute(
            rtcbase::make_unique<StunXorAddressAttribute>(STUN_ATTR_XOR_MAPPED_ADDRESS, addr));
    response.add_message_integrity(_password);
    response.add_fingerprint();

    // Send the response message.
    rtcbase::ByteBufferWriter buf;
    response.write(&buf);
    rtcbase::PacketOptions options(default_dscp_value());
    auto err = send_to(buf.data(), buf.length(), addr, options, false);
    Connection* conn = get_connection(addr);
    if (err < 0) {
        LOG_J(LS_WARNING, conn)
            << "Failed to send STUN ping response"
            << ", to=" << addr.to_sensitive_string()
            << ", err=" << err
            << ", id=" << rtcbase::hex_encode(response.transaction_id());
    } else {
        // Log at LS_INFO if we send a stun ping response on an unwritable
        // connection.
        LOG_J(LS_TRACE, conn)
            << "Sent STUN ping response"
            << ", to=" << addr.to_sensitive_string()
            << ", id=" << rtcbase::hex_encode(response.transaction_id());
    }
}

void Port::send_binding_error_response(StunMessage* request,
        const rtcbase::SocketAddress& addr,
        int error_code, const std::string& reason) 
{
    if (request->type() != STUN_BINDING_REQUEST) {
        return;
    }

    // Fill in the response message.
    StunMessage response;
    response.set_type(STUN_BINDING_ERROR_RESPONSE);
    response.set_transaction_ID(request->transaction_id());

    // When doing GICE, we need to write out the error code incorrectly to
    // maintain backwards compatiblility.
    auto error_attr = StunAttribute::create_error_code();
    error_attr->set_code(error_code);
    error_attr->set_reason(reason);
    response.add_attribute(std::move(error_attr));

    // Per Section 10.1.2, certain error cases don't get a MESSAGE-INTEGRITY,
    // because we don't have enough information to determine the shared secret.
    if (error_code != STUN_ERROR_BAD_REQUEST &&
            error_code != STUN_ERROR_UNAUTHORIZED)
    {
        response.add_message_integrity(_password);
    }
    response.add_fingerprint();

    // Send the response message.
    rtcbase::ByteBufferWriter buf;
    response.write(&buf);
    rtcbase::PacketOptions options(default_dscp_value());
    send_to(buf.data(), buf.length(), addr, options, false);
    LOG_J(LS_WARNING, this) << "Sending STUN binding error: reason=" << reason
        << " to " << addr.to_sensitive_string();
}

void Port::add_address(const rtcbase::SocketAddress& address,
        const rtcbase::SocketAddress& base_address,
        const rtcbase::SocketAddress& related_address,
        const std::string& protocol,
        const std::string& relay_protocol,
        const std::string& tcptype,
        const std::string& type,
        uint32_t type_preference,
        uint32_t relay_preference,
        bool last) 
{
    if (protocol == TCP_PROTOCOL_NAME && type == HOST_PORT_TYPE) {
        if (tcptype.empty()) {
            return;
        }
    }
    
    std::string foundation =
        compute_foundation(type, protocol, relay_protocol, base_address);
    Candidate c(_component, protocol, address, 0U, username_fragment(), _password,
            type, _generation, foundation, _network->id(), _network_cost);
    c.set_transport_name(_content_name);
    c.set_priority(
            c.get_priority(type_preference, _network->preference(), relay_preference));
    c.set_relay_protocol(relay_protocol);
    c.set_tcptype(tcptype);
    c.set_network_name(_network->name());
    c.set_network_type(_network->type());
    c.set_related_address(related_address);
    _candidates.push_back(c);
    signal_candidate_ready(this, c);
    
    if (last) {
        signal_port_complete(this);
    }
}

void Port::add_or_replace_connection(Connection* conn) {
    auto ret = _connections.insert(
            std::make_pair(conn->remote_candidate().address(), conn));
    // If there is a different connection on the same remote address, replace
    // it with the new one and destroy the old one.
    if (ret.second == false && ret.first->second != conn) {
        LOG_J(LS_WARNING, this)
            << "A new connection was created on an existing remote address. "
            << "New remote candidate: " << conn->remote_candidate().to_string();
        ret.first->second->signal_destroyed.disconnect(this);
        ret.first->second->destroy();
        ret.first->second = conn;
    }
    conn->set_log_trace_id(get_log_trace_id());
    conn->signal_destroyed.connect(this, &Port::on_connection_destroyed);
    signal_connection_created(this, conn);
}

void Port::on_read_packet(
        const char* data, size_t size, const rtcbase::SocketAddress& addr,
        ProtocolType proto) 
{  
    // If the user has enabled port packets, just hand this over.
    if (_enable_port_packets) {
        //signal_read_packet(this, data, size, addr);
        return;
    }
    
    // If this is an authenticated STUN request, then signal unknown address and
    // send back a proper binding response.
    std::unique_ptr<IceMessage> msg;
    std::string remote_username;
    if (!get_stun_message(data, size, addr, &msg, &remote_username)) {
        LOG_J(LS_WARNING, this) << "Received non-STUN packet from unknown address ("
            << addr.to_sensitive_string() << ")";
    } else if (!msg) {
        // STUN message handled already
    } else if (msg->type() == STUN_BINDING_REQUEST) {
        LOG_J(LS_TRACE, this) << "Received STUN ping "
            << " id=" << rtcbase::hex_encode(msg->transaction_id())
            << " from unknown address " << addr.to_sensitive_string();
        
        // Check for role conflicts.
        if (!maybe_ice_role_conflict(addr, msg.get(), remote_username)) {
            LOG(LS_TRACE) << "Received conflicting role from the peer.";
            return;
        }

        signal_unknown_address(this, addr, proto, msg.get(), remote_username, false);
    } else {
        // NOTE(tschmelcher): STUN_BINDING_RESPONSE is benign. It occurs if we
        // pruned a connection for this port while it had STUN requests in flight,
        // because we then get back responses for them, which this code correctly
        // does not handle.
        if (msg->type() != STUN_BINDING_RESPONSE) {
            LOG_J(LS_WARNING, this) << "Received unexpected STUN message type ("
                << msg->type() << ") from unknown address ("
                << addr.to_sensitive_string() << ")";
        }
    }
}

bool Port::get_stun_message(const char* data,
        size_t size,
        const rtcbase::SocketAddress& addr,
        std::unique_ptr<IceMessage>* out_msg,
        std::string* out_username) 
{
    // NOTE: This could clearly be optimized to avoid allocating any memory.
    //       However, at the data rates we'll be looking at on the client side,
    //       this probably isn't worth worrying about.
    if (out_msg == NULL || out_username == NULL) {
        return false;
    }
    out_username->clear();

    // Don't bother parsing the packet if we can tell it's not STUN.
    // In ICE mode, all STUN packets will have a valid fingerprint.
    if (!StunMessage::validate_fingerprint(data, size)) {
        return false;
    }
    
    // Parse the request message.  If the packet is not a complete and correct
    // STUN message, then ignore it.
    std::unique_ptr<IceMessage> stun_msg(new IceMessage());
    rtcbase::ByteBufferReader buf(data, size);
    if (!stun_msg->read(&buf) || (buf.length() > 0)) {
        return false;
    }
    
    if (stun_msg->type() == STUN_BINDING_REQUEST) {
        // Check for the presence of USERNAME and MESSAGE-INTEGRITY (if ICE) first.
        // If not present, fail with a 400 Bad Request.
        if (!stun_msg->get_byte_string(STUN_ATTR_USERNAME) ||
                !stun_msg->get_byte_string(STUN_ATTR_MESSAGE_INTEGRITY)) {
            LOG_J(LS_WARNING, this) << "Received STUN request without username/M-I "
                << "from " << addr.to_sensitive_string();
            send_binding_error_response(stun_msg.get(), addr, STUN_ERROR_BAD_REQUEST,
                    STUN_ERROR_REASON_BAD_REQUEST);
            return true;
        }
        
        // If the username is bad or unknown, fail with a 401 Unauthorized.
        std::string local_ufrag;
        std::string remote_ufrag;
        if (!parse_stun_username(stun_msg.get(), &local_ufrag, &remote_ufrag) ||
                local_ufrag != username_fragment()) {
            LOG_J(LS_WARNING, this) << "Received STUN request with bad local username "
                << local_ufrag << " from "
                << addr.to_sensitive_string();
            send_binding_error_response(stun_msg.get(), addr, STUN_ERROR_UNAUTHORIZED,
                    STUN_ERROR_REASON_UNAUTHORIZED);
            return true;
        }
        
        // If ICE, and the MESSAGE-INTEGRITY is bad, fail with a 401 Unauthorized
        if (!stun_msg->validate_message_integrity(data, size, _password)) {
            LOG_J(LS_WARNING, this) << "Received STUN request with bad M-I "
                << "from " << addr.to_sensitive_string()
                << ", _password=" << _password;
            send_binding_error_response(stun_msg.get(), addr, STUN_ERROR_UNAUTHORIZED,
                    STUN_ERROR_REASON_UNAUTHORIZED);
            return true;
        }
        out_username->assign(remote_ufrag);
    } else if ((stun_msg->type() == STUN_BINDING_RESPONSE) ||
            (stun_msg->type() == STUN_BINDING_ERROR_RESPONSE)) 
    {
        if (stun_msg->type() == STUN_BINDING_ERROR_RESPONSE) 
        {
            if (const StunErrorCodeAttribute* error_code = stun_msg->get_error_code()) {
                LOG_J(LS_WARNING, this) << "Received STUN binding error:"
                    << " class=" << error_code->eclass()
                    << " number=" << error_code->number()
                    << " reason='" << error_code->reason() << "'"
                    << " from " << addr.to_sensitive_string();
                // Return message to allow error-specific processing
            } else {
                LOG_J(LS_WARNING, this) << "Received STUN binding error without a error "
                    << "code from " << addr.to_sensitive_string();
                return true;
            }
        }
        // NOTE: Username should not be used in verifying response messages.
        out_username->clear();
    } else if (stun_msg->type() == STUN_BINDING_INDICATION) {
        LOG_J(LS_TRACE, this) << "Received STUN binding indication:"
            << " from " << addr.to_sensitive_string();
        out_username->clear();
        // No stun attributes will be verified, if it's stun indication message.
        // Returning from end of the this method.
    } else {
        LOG_J(LS_WARNING, this) << "Received STUN packet with invalid type ("
            << stun_msg->type() << ") from "
            << addr.to_sensitive_string();
        return true;
    }

    // Return the STUN message found.
    *out_msg = std::move(stun_msg);
    return true;
}

bool Port::is_compatible_address(const rtcbase::SocketAddress& addr) {
    int family = ip().family();
    // We use single-stack sockets, so families must match.
    if (addr.family() != family) {
        return false;
    }
    // Link-local IPv6 ports can only connect to other link-local IPv6 ports.
    if (family == AF_INET6 &&
            (IP_is_link_local(ip()) != IP_is_link_local(addr.ipaddr()))) 
    {
        return false;
    }
    return true;
}

const std::string Port::username_fragment() const {
    return _ice_username_fragment;
}

std::string Port::to_string() const {
    std::stringstream ss;
    ss << "Port[trace_id=" << get_log_trace_id() 
        << " content_name=" << _content_name 
        << " component=" << _component 
        << " generation=" << _generation 
        << " type=" << _type
        << " " << _network->to_string() 
        << "]";
    return ss.str();
}

bool Port::parse_stun_username(const StunMessage* stun_msg,
        std::string* local_ufrag,
        std::string* remote_ufrag) const 
{
    // The packet must include a username that either begins or ends with our
    // fragment.  It should begin with our fragment if it is a request and it
    // should end with our fragment if it is a response.
    local_ufrag->clear();
    remote_ufrag->clear();
    const StunByteStringAttribute* username_attr =
        stun_msg->get_byte_string(STUN_ATTR_USERNAME);
    if (username_attr == NULL) {
        return false;
    }

    // RFRAG:LFRAG
    const std::string username = username_attr->get_string();
    size_t colon_pos = username.find(":");
    if (colon_pos == std::string::npos) {
        return false;
    }

    *local_ufrag = username.substr(0, colon_pos);
    *remote_ufrag = username.substr(colon_pos + 1, username.size());
    return true;
}

void Port::create_stun_username(const std::string& remote_username,
        std::string* stun_username_attr_str) const 
{
    stun_username_attr_str->clear();
    *stun_username_attr_str = remote_username;
    stun_username_attr_str->append(":");
    stun_username_attr_str->append(username_fragment());
}

bool Port::maybe_ice_role_conflict(
        const rtcbase::SocketAddress& addr, IceMessage* stun_msg,
        const std::string& remote_ufrag) 
{
    // Validate ICE_CONTROLLING or ICE_CONTROLLED attributes.
    bool ret = true;
    IceRole remote_ice_role = ICEROLE_UNKNOWN;
    uint64_t remote_tiebreaker = 0;
    const StunUInt64Attribute* stun_attr =
        stun_msg->get_uint64(STUN_ATTR_ICE_CONTROLLING);
    if (stun_attr) {
        remote_ice_role = ICEROLE_CONTROLLING;
        remote_tiebreaker = stun_attr->value();
    }

    // If |remote_ufrag| is same as port local username fragment and
    // tie breaker value received in the ping message matches port
    // tiebreaker value this must be a loopback call.
    // We will treat this as valid scenario.
    if (remote_ice_role == ICEROLE_CONTROLLING &&
            username_fragment() == remote_ufrag &&
            remote_tiebreaker == ice_tiebreaker()) {
        return true;
    }

    stun_attr = stun_msg->get_uint64(STUN_ATTR_ICE_CONTROLLED);
    if (stun_attr) {
        remote_ice_role = ICEROLE_CONTROLLED;
        remote_tiebreaker = stun_attr->value();
    }

    switch (_ice_role) {
        case ICEROLE_CONTROLLING:
            if (ICEROLE_CONTROLLING == remote_ice_role) {
                if (remote_tiebreaker >= _tiebreaker) {
                    //SignalRoleConflict(this);
                } else {
                    // Send Role Conflict (487) error response.
                    send_binding_error_response(stun_msg, addr,
                            STUN_ERROR_ROLE_CONFLICT, STUN_ERROR_REASON_ROLE_CONFLICT);
                    ret = false;
                }
            }
            break;
        case ICEROLE_CONTROLLED:
            if (ICEROLE_CONTROLLED == remote_ice_role) {
                if (remote_tiebreaker < _tiebreaker) {
                    //SignalRoleConflict(this);
                } else {
                    // Send Role Conflict (487) error response.
                    send_binding_error_response(stun_msg, addr,
                            STUN_ERROR_ROLE_CONFLICT, STUN_ERROR_REASON_ROLE_CONFLICT);
                    ret = false;
                }
            }
            break;
        default:
            //ASSERT(false);
            break;
    }
    return ret;
}

size_t Port::add_prflx_candidate(const Candidate& local) {
    _candidates.push_back(local);
    return (_candidates.size() - 1);
}

// A ConnectionRequest is a simple STUN ping used to determine writability.
class ConnectionRequest : public StunRequest {
public:
    explicit ConnectionRequest(Connection* connection)
        : StunRequest(connection->port()->event_loop(), 
                new IceMessage()),
        _connection(connection) {}

    virtual ~ConnectionRequest() {}
    
    void prepare(StunMessage* request) override {
        request->set_type(STUN_BINDING_REQUEST);
        // USERNAME
        std::string username;
        _connection->port()->create_stun_username(
                _connection->remote_candidate().username(), &username);
        request->add_attribute(
                rtcbase::make_unique<StunByteStringAttribute>(STUN_ATTR_USERNAME, username));
       
        // NETWORK_INFO
        uint32_t network_info = _connection->port()->network()->id();
        network_info = (network_info << 16) | _connection->port()->network_cost();
        request->add_attribute(
                rtcbase::make_unique<StunUInt32Attribute>(STUN_ATTR_NETWORK_INFO, network_info));
        
        // ICE_CONTROLLED or ICE_CONTROLLING
        if (_connection->port()->get_ice_role() == ICEROLE_CONTROLLING) {
            request->add_attribute(rtcbase::make_unique<StunUInt64Attribute>(
                        STUN_ATTR_ICE_CONTROLLING, _connection->port()->ice_tiebreaker()));
            // We should have either USE_CANDIDATE attribute or ICE_NOMINATION
            // attribute but not both. That was enforced in p2ptransportchannel.
            if (_connection->use_candidate_attr()) {
                request->add_attribute(rtcbase::make_unique<StunByteStringAttribute>(
                            STUN_ATTR_USE_CANDIDATE));
            }
            if (_connection->nomination() &&
                    _connection->nomination() != _connection->acked_nomination()) {
                request->add_attribute(rtcbase::make_unique<StunUInt32Attribute>(
                            STUN_ATTR_NOMINATION, _connection->nomination()));
            }
        } else if (_connection->port()->get_ice_role() == ICEROLE_CONTROLLED) {
            request->add_attribute(rtcbase::make_unique<StunUInt64Attribute>(
                        STUN_ATTR_ICE_CONTROLLED, _connection->port()->ice_tiebreaker()));
        }

        // Adding PRIORITY Attribute.
        // Changing the type preference to Peer Reflexive and local preference
        // and component id information is unchanged from the original priority.
        // priority = (2^24)*(type preference) +
        //           (2^8)*(local preference) +
        //           (2^0)*(256 - component ID)
        uint32_t type_preference =
            (_connection->local_candidate().protocol() == TCP_PROTOCOL_NAME)
            ? ICE_TYPE_PREFERENCE_PRFLX_TCP
            : ICE_TYPE_PREFERENCE_PRFLX;
        uint32_t prflx_priority =
            type_preference << 24 |
            (_connection->local_candidate().priority() & 0x00FFFFFF);
        request->add_attribute(
                rtcbase::make_unique<StunUInt32Attribute>(STUN_ATTR_PRIORITY, prflx_priority));
        
        // Adding Message Integrity attribute.
        request->add_message_integrity(_connection->remote_candidate().password());
        // Adding Fingerprint.
        request->add_fingerprint();
    }
    
    void on_response(StunMessage* response) override {
        _connection->on_connection_request_response(this, response);
    }
    
    void on_error_response(StunMessage* response) override {
        _connection->on_connection_request_error_response(this, response);
    }
    
    void on_timeout() override {
        _connection->on_connection_request_timeout(this);
    }

    void on_sent() override {
        _connection->on_connection_request_sent(this);
        // Each request is sent only once.  After a single delay , the request will
        // time out.
        _timeout = true;
    }
    
    int resend_delay() override {
        return CONNECTION_RESPONSE_TIMEOUT;
    }

private:
    Connection* _connection;
};

//////////////////// Connection //////////////////

Connection::Connection(Port* port,
        size_t index,
        const Candidate& remote_candidate)
    : MemCheck("Connection"), 
    _port(port),
    _local_candidate_index(index),
    _remote_candidate(remote_candidate),
    _write_state(STATE_WRITE_INIT),
    _receiving(false),
    _connected(true),
    _pruned(false),
    _use_candidate_attr(false),
    _remote_ice_mode(ICEMODE_FULL),
    _requests(),
    _rtt(DEFAULT_RTT),
    _last_ping_sent(0),
    _last_ping_received(0),
    _last_data_received(0),
    _last_ping_response_received(0),
    _state(IceCandidatePairState::WAITING),
    _receiving_timeout(WEAK_CONNECTION_RECEIVE_TIMEOUT),
    _time_created_ms(rtcbase::time_millis()) 
{
    // All of our connections start in WAITING state.
    // TODO(mallinath) - Start connections from STATE_FROZEN.
    // Wire up to send stun packets
    _requests.signal_send_packet.connect(this, &Connection::on_send_stun_packet);
    LOG_J(LS_TRACE, this) << "Connection created";
}

Connection::~Connection() {}

const Candidate& Connection::local_candidate() const {
    return _port->candidates()[_local_candidate_index];
}

const Candidate& Connection::remote_candidate() const {
    return _remote_candidate;
}

uint64_t Connection::priority() const {
    uint64_t priority = 0;
    // RFC 5245 - 5.7.2.  Computing Pair Priority and Ordering Pairs
    // Let G be the priority for the candidate provided by the controlling
    // agent.  Let D be the priority for the candidate provided by the
    // controlled agent.
    // pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    IceRole role = _port->get_ice_role();
    if (role != ICEROLE_UNKNOWN) {
        uint32_t g = 0;
        uint32_t d = 0;
        if (role == ICEROLE_CONTROLLING) {
            g = local_candidate().priority();
            d = _remote_candidate.priority();
        } else {
            g = _remote_candidate.priority();
            d = local_candidate().priority();
        }
        priority = std::min(g, d);
        priority = priority << 32;
        priority += 2 * std::max(g, d) + (g > d ? 1 : 0);
    }
    return priority;
}

void Connection::set_write_state(WriteState value) {
    WriteState old_value = _write_state;
    _write_state = value;
    if (value != old_value) {
        LOG_J(LS_TRACE, this) << "set_write_state from: " << old_value << " to "
            << value;
        signal_state_change(this);
    }
}

void Connection::update_receiving(int64_t now) {
    bool receiving;
    if (last_ping_sent() > 0 && last_ping_sent() <= last_ping_response_received()) {
        receiving = true;
    } else {
        receiving = 
            (last_received() > 0 && now <= (last_received() + _receiving_timeout))
                || _pings_since_last_response.size() <= 1; // 由于备用连接ping发送周期较长，避免误判
    }
    if (_receiving == receiving) {
        return;
    }
    _receiving = receiving;
    LOG_J(LS_TRACE, this) << "set_receiving to " << receiving; 
    _receiving_unchanged_since = now;
    signal_state_change(this);
}

void Connection::set_state(IceCandidatePairState state) {
    IceCandidatePairState old_state = _state;
    _state = state;
    if (state != old_state) {
        //LOG_J(LS_TRACE, this) << "set_state";
    }
}

void Connection::update_state(int64_t now) {
    int rtt = conservative_RTT_estimate(_rtt);
    
    /*
    std::string pings;
    print_pings_since_last_response(&pings, 5);
    LOG_J(LS_TRACE, this) << "UpdateState()"
        << ", ms since last received response="
        << now - _last_ping_response_received
        << ", ms since last received data="
        << now - _last_data_received
        << ", rtt=" << rtt
        << ", pings_since_last_response=" << pings;
    */

    // Check the writable state.  (The order of these checks is important.)
    //
    // Before becoming unwritable, we allow for a fixed number of pings to fail
    // (i.e., receive no response).  We also have to give the response time to
    // get back, so we include a conservative estimate of this.
    //
    // Before timing out writability, we give a fixed amount of time.  This is to
    // allow for changes in network conditions.
    
    if ((_write_state == STATE_WRITABLE) &&
            too_many_failures(_pings_since_last_response,
                CONNECTION_WRITE_CONNECT_FAILURES,
                rtt,
                now) &&
            too_long_without_response(_pings_since_last_response,
                CONNECTION_WRITE_CONNECT_TIMEOUT,
                now)) 
    {
        uint32_t max_pings = CONNECTION_WRITE_CONNECT_FAILURES;
        LOG_J(LS_TRACE, this) << "Unwritable after " << max_pings
            << " ping failures and "
            << now - _pings_since_last_response[0].sent_time
            << " ms without a response,"
            << " last_received_ping=" << "ms"
            << now - _last_ping_received
            << " last_received_data="
            << now - _last_data_received << "ms"
            << " rtt=" << rtt;
        set_write_state(STATE_WRITE_UNRELIABLE);
        return;
    }

    if ((_write_state == STATE_WRITE_UNRELIABLE ||
                _write_state == STATE_WRITE_INIT) &&
            too_long_without_response(_pings_since_last_response,
                CONNECTION_WRITE_TIMEOUT,
                now)) 
    {
        LOG_J(LS_TRACE, this) << "Timed out after "
            << now - _pings_since_last_response[0].sent_time
            << " ms without a response"
            << ", rtt=" << rtt;
        set_write_state(STATE_WRITE_TIMEOUT);
        return;
    }
    
    // Update the receiving state.
    update_receiving(now);
    if (dead(now)) {
        destroy();
    }
}

void Connection::ping(int64_t now) {
    _last_ping_sent = now;
    ConnectionRequest* req = new ConnectionRequest(this);
    // If not using renomination, we use "1" to mean "nominated" and "0" to mean
    // "not nominated". If using renomination, values greater than 1 are used for
    // re-nominated pairs.
    int nomination = _use_candidate_attr ? 1 : 0;
    if (_nomination > 0) {
        nomination = _nomination;
    }

    _pings_since_last_response.push_back(SentPing(req->id(), now, nomination));
    /*
    LOG_J(LS_TRACE, this) << "Sending STUN ping "
        << ", id=" << rtcbase::hex_encode(req->id())
        << ", nomination=" << _nomination;
    */
    _requests.send(req);
    _state = IceCandidatePairState::INPROGRESS;
    _num_pings_sent++;
}

void Connection::received_ping_response(int rtt, const std::string& request_id) {
    // We've already validated that this is a STUN binding response with
    // the correct local and remote username for this connection.
    // So if we're not already, become writable. We may be bringing a pruned
    // connection back to life, but if we don't really want it, we can always
    // prune it again.
    auto iter = std::find_if(
            _pings_since_last_response.begin(), _pings_since_last_response.end(),
            [request_id](const SentPing& ping) { return ping.id == request_id; });
    if (iter != _pings_since_last_response.end() &&
            iter->nomination > _acked_nomination) {
        _acked_nomination = iter->nomination;
    }

    _pings_since_last_response.clear();
    _last_ping_response_received = rtcbase::time_millis();
    update_receiving(_last_ping_response_received);
    if (_rtt_samples > 0) {
        _rtt = (RTT_RATIO * _rtt + rtt) / (RTT_RATIO + 1); 
    } else {
        _rtt = rtt;
    }
    _rtt_samples++;
    set_write_state(STATE_WRITABLE);
    set_state(IceCandidatePairState::SUCCEEDED);
}

bool Connection::dead(int64_t now) const { 
    if (last_received() > 0) { 
        // If it has ever received anything, we keep it alive until it hasn't
        // received anything for DEAD_CONNECTION_RECEIVE_TIMEOUT. This covers the
        // normal case of a successfully used connection that stops working. This
        // also allows a remote peer to continue pinging over a locally inactive
        // (pruned) connection.
        return (now > (last_received() + DEAD_CONNECTION_RECEIVE_TIMEOUT));
    }
      
    if (active()) {
        // If it has never received anything, keep it alive as long as it is
        // actively pinging and not pruned. Otherwise, the connection might be
        // deleted before it has a chance to ping. This is the normal case for a
        // new connection that is pinging but hasn't received anything yet.
        return false;
    }
 
    // If it has never received anything and is not actively pinging (pruned), we
    // keep it around for at least MIN_CONNECTION_LIFETIME to prevent connections
    // from being pruned too quickly during a network change event when two
    // networks would be up simultaneously but only for a brief period.
    return now > (_time_created_ms + MIN_CONNECTION_LIFETIME);
}

bool Connection::stable(int64_t now) const {
    // A connection is stable if it's RTT has converged and it isn't missing any
    // responses.  We should send pings at a higher rate until the RTT converges
    // and whenever a ping response is missing (so that we can detect
    // unwritability faster)
    return rtt_converged() && !missing_responses(now);
}

void Connection::received_ping() {
    _last_ping_received = rtcbase::time_millis();
    update_receiving(_last_ping_received);
}

void Connection::handle_binding_request(IceMessage* msg) {
    // This connection should now be receiving.
    received_ping();
    
    const rtcbase::SocketAddress& remote_addr = _remote_candidate.address();
    const std::string& remote_ufrag = _remote_candidate.username();
    // Check for role conflicts.
    if (!_port->maybe_ice_role_conflict(remote_addr, msg, remote_ufrag)) {
        // Received conflicting role from the peer.
        LOG(LS_TRACE) << "Received conflicting role from the peer.";
        return;
    }
    
    //stats_.recv_ping_requests++;

    // This is a validated stun request from remote peer.
    _port->send_binding_response(msg, remote_addr);
    
    // If it timed out on writing check, start up again
    if (!_pruned && _write_state == STATE_WRITE_TIMEOUT) {
        set_write_state(STATE_WRITE_INIT);
    }
    
    if (_port->get_ice_role() == ICEROLE_CONTROLLED) {
        const StunUInt32Attribute* nomination_attr =
            msg->get_uint32(STUN_ATTR_NOMINATION);
        uint32_t nomination = 0;
        if (nomination_attr) {
            nomination = nomination_attr->value();
            if (nomination == 0) {
                LOG(LS_WARNING) << "Invalid nomination: " << nomination;
            }
        } else {
            const StunByteStringAttribute* use_candidate_attr =
                msg->get_byte_string(STUN_ATTR_USE_CANDIDATE);
            if (use_candidate_attr) {
                nomination = 1;
            }
        }
        // We don't un-nominate a connection, so we only keep a larger nomination.
        if (nomination > _remote_nomination) {
            set_remote_nomination(nomination);
            signal_nominated(this);
        }
    }
    
    // Set the remote cost if the network_info attribute is available.
    // Note: If packets are re-ordered, we may get incorrect network cost
    // temporarily, but it should get the correct value shortly after that.
    const StunUInt32Attribute* network_attr =
        msg->get_uint32(STUN_ATTR_NETWORK_INFO);
    if (network_attr) {
        uint32_t network_info = network_attr->value();
        uint16_t network_cost = static_cast<uint16_t>(network_info);
        if (network_cost != _remote_candidate.network_cost()) {
            _remote_candidate.set_network_cost(network_cost);
            // Network cost change will affect the connection ranking, so signal
            // state change to force a re-sort in P2PTransportChannel.
            signal_state_change(this);
        }
    }
}

std::string Connection::to_debug_id() const {
    std::stringstream ss;
    ss << std::hex << this;
    return ss.str();
}

std::string Connection::to_string() {
    const std::string CONNECT_STATE_ABBREV[2] = {
        "false",  // not connected (false)
        "true",   // connected (true)
    };
    const std::string RECEIVE_STATE_ABBREV[2] = {
        "false",  // not receiving (false)
        "true",   // receiving (true)
    };
    const std::string WRITE_STATE_ABBREV[4] = {
        "writeable",   // STATE_WRITABLE
        "unrelialbe",  // STATE_WRITE_UNRELIABLE
        "init",        // STATE_WRITE_INIT
        "timeout",     // STATE_WRITE_TIMEOUT
    };
    const std::string ICESTATE[4] = {
        "waiting",  // STATE_WAITING
        "inprogress",  // STATE_INPROGRESS
        "succeeded",  // STATE_SUCCEEDED
        "failed"   // STATE_FAILED
    };
    const Candidate& local = local_candidate();
    const Candidate& remote = remote_candidate();
    int64_t now = rtcbase::time_millis();
    
    std::stringstream ss;
    int64_t last_ping_response_received = _last_ping_response_received > 0 ?
        now - _last_ping_response_received : -1;
    int64_t last_data_received = _last_data_received > 0 ?
        now -_last_data_received : -1;

    ss << "Conn[trace_id=" << get_log_trace_id()
       << " " << local.address().to_sensitive_string() << ":" << local.component() 
       << ":" << local.priority()
       << ":" << local.type() << ":" << local.protocol()
       << "-->" << remote.address().to_sensitive_string() << ":" << remote.component() 
       << ":" << remote.priority()
       << ":" << remote.type() << ":" << remote.protocol()
       << " transport_name=" << _port->content_name() 
       << " connect_state=" << CONNECT_STATE_ABBREV[connected()]
       << " receive_state=" << RECEIVE_STATE_ABBREV[receiving()] 
       << " write_state=" << WRITE_STATE_ABBREV[write_state()]
       << " ice_state=" << ICESTATE[int(state())] 
       << " selected=" << selected()
       << " remote_nomination=" << remote_nomination() 
       << " nomination=" << nomination()
       << " priority=" << priority()
       << " last_ping_response_received=" << last_ping_response_received << "ms"
       << " last_data_received=" << last_data_received << "ms"
       << " rtt=" << _rtt << "ms"
       << " conn=" << this
       << "]";

    return ss.str();
}

uint32_t Connection::compute_network_cost() const {
    // TODO(honghaiz): Will add rtt as part of the network cost.
    return port()->network_cost() + _remote_candidate.network_cost();
}

void Connection::handle_role_conflict_from_peer() {
    _port->signal_role_conflict(_port);
}

void Connection::maybe_set_remote_ice_credentials_and_generation(
        const IceParameters& ice_params,
        int generation) 
{
    if (_remote_candidate.username() == ice_params.ufrag &&
            _remote_candidate.password().empty()) 
    {
        _remote_candidate.set_password(ice_params.pwd);
    }
    // TODO(deadbeef): A value of '0' for the generation is used for both
    // generation 0 and "generation unknown". It should be changed to an
    // rtc::Optional to fix this.
    if (_remote_candidate.username() == ice_params.ufrag &&
            _remote_candidate.password() == ice_params.pwd &&
            _remote_candidate.generation() == 0) 
    {
        _remote_candidate.set_generation(generation);
    }
}

void Connection::maybe_update_peer_reflexive_candidate(
        const Candidate& new_candidate) 
{
    if (_remote_candidate.type() == PRFLX_PORT_TYPE &&
            new_candidate.type() != PRFLX_PORT_TYPE &&
            _remote_candidate.protocol() == new_candidate.protocol() &&
            _remote_candidate.address() == new_candidate.address() &&
            _remote_candidate.username() == new_candidate.username() &&
            _remote_candidate.password() == new_candidate.password() &&
            _remote_candidate.generation() == new_candidate.generation()) 
    {
        _remote_candidate = new_candidate;
    }
}

int64_t Connection::last_received() const {
    return std::max(_last_data_received,
            std::max(_last_ping_received, _last_ping_response_received));
}

void Connection::on_read_packet(
        const char* data, size_t size, 
        const rtcbase::PacketTime& packet_time) 
{
    std::unique_ptr<IceMessage> msg;
    std::string remote_ufrag;
    const rtcbase::SocketAddress& addr(_remote_candidate.address());
    if (!_port->get_stun_message(data, size, addr, &msg, &remote_ufrag)) {
        // The packet did not parse as a valid STUN message
        // This is a data packet, pass it along.
        _last_data_received = rtcbase::time_millis();
        update_receiving(_last_data_received);
        //recv_rate_tracker_.AddSamples(size);
        signal_read_packet(this, data, size, packet_time);

        // If timed out sending writability checks, start up again
        if (!_pruned && (_write_state == STATE_WRITE_TIMEOUT)) {
            LOG(LS_WARNING) << "Received a data packet on a timed-out Connection. "
                << "Resetting state to STATE_WRITE_INIT.";
            set_write_state(STATE_WRITE_INIT);
        }
    } else if (!msg) {
        // The packet was STUN, but failed a check and was handled internally.
    } else {
        // The packet is STUN and passed the Port checks.
        // Perform our own checks to ensure this packet is valid.
        // If this is a STUN request, then update the receiving bit and respond.
        // If this is a STUN response, then update the writable bit.
        // Log at LS_INFO if we receive a ping on an unwritable connection.
        switch (msg->type()) {
            case STUN_BINDING_REQUEST:
                LOG_J(LS_TRACE, this) << "Received STUN ping"
                    << ", id=" << rtcbase::hex_encode(msg->transaction_id());

                if (remote_ufrag == _remote_candidate.username()) {
                    handle_binding_request(msg.get());
                } else {
                    // The packet had the right local username, but the remote username
                    // was not the right one for the remote address.
                    LOG_J(LS_WARNING, this)
                        << "Received STUN request with bad remote username "
                        << remote_ufrag;
                    _port->send_binding_error_response(msg.get(), addr,
                            STUN_ERROR_UNAUTHORIZED,
                            STUN_ERROR_REASON_UNAUTHORIZED);

                }
                break;
                // Response from remote peer. Does it match request sent?
                // This doesn't just check, it makes callbacks if transaction
                // id's match.
            case STUN_BINDING_RESPONSE:
            case STUN_BINDING_ERROR_RESPONSE:
                if (msg->validate_message_integrity(
                            data, size, remote_candidate().password())) {
                    _requests.check_response(msg.get());
                }
                // Otherwise silently discard the response message.
                break;
                // Remote end point sent an STUN indication instead of regular binding
                // request. In this case |last_ping_received_| will be updated but no
                // response will be sent.
            case STUN_BINDING_INDICATION:
                received_ping();
                break;
            default:
                break;
        }
    }
}

void Connection::set_use_candidate_attr(bool enable) {
    _use_candidate_attr = enable;
}

void Connection::on_send_stun_packet(const void* data, size_t size,
        StunRequest* req) 
{
    rtcbase::PacketOptions options(_port->default_dscp_value());
    auto err = _port->send_to(
            data, size, _remote_candidate.address(), options, false);
    if (err < 0) {
        LOG_J(LS_WARNING, this) << "Failed to send STUN ping "
            << " err=" << err
            << " id=" << rtcbase::hex_encode(req->id());
    }
}

void Connection::on_connection_request_response(ConnectionRequest* request,
        StunMessage* response) 
{
    int rtt = request->elapsed();

    std::string pings;
    print_pings_since_last_response(&pings, 5);
    LOG_J(LS_TRACE, this) << "Received STUN ping response"
        << ", id=" << rtcbase::hex_encode(request->id())
        << ", code=0"  // Makes logging easier to parse.
        << ", rtt=" << rtt << "ms"
        << ", pings_since_last_response=" << pings;
    received_ping_response(rtt, request->id());

    maybe_update_local_candidate(request, response);
}

void Connection::on_connection_request_error_response(ConnectionRequest* request,
        StunMessage* response) 
{
    const StunErrorCodeAttribute* error_attr = response->get_error_code();
    int error_code = STUN_ERROR_GLOBAL_FAILURE;
    if (error_attr) {
        error_code = error_attr->code();
    }

    LOG_J(LS_TRACE, this) << "Received STUN error response"
        << " id=" << rtcbase::hex_encode(request->id())
        << " code=" << error_code
        << " rtt=" << request->elapsed();

    if (error_code == STUN_ERROR_UNKNOWN_ATTRIBUTE ||
            error_code == STUN_ERROR_SERVER_ERROR ||
            error_code == STUN_ERROR_UNAUTHORIZED) {
        // Recoverable error, retry
    } else if (error_code == STUN_ERROR_STALE_CREDENTIALS) {
        // Race failure, retry
    } else if (error_code == STUN_ERROR_ROLE_CONFLICT) {
        handle_role_conflict_from_peer();
    } else {
        // This is not a valid connection.
        LOG_J(LS_WARNING, this) << "Received STUN error response, code="
            << error_code << "; killing connection";
        fail_and_destroy();
    }
}

void Connection::on_connection_request_timeout(ConnectionRequest* request) {
    // Log at LS_INFO if we miss a ping on a writable connection.
    LOG_J(LS_TRACE, this) << "Timing-out STUN ping "
        << rtcbase::hex_encode(request->id())
        << " after " << request->elapsed() << " ms";
}

void Connection::on_connection_request_sent(ConnectionRequest* request) {
    LOG_J(LS_TRACE, this) << "Sent STUN ping"
        << ", id=" << rtcbase::hex_encode(request->id())
        << ", use_candidate=" << use_candidate_attr()
        << ", nomination=" << nomination();
}

void Connection::prune() {
    if (!_pruned || active()) {
        LOG(LS_NOTICE) << to_string() << ": Connection pruned";
        _pruned = true;
        _requests.clear();
        set_write_state(STATE_WRITE_TIMEOUT);
    }
}

void Connection::destroy() {
    LOG_J(LS_TRACE, this) << "Connection destroyed";
    LOG_J(LS_TRACE, this) << "Connection deleted with number of pings sent: "
        << _num_pings_sent;
    signal_destroyed(this);
}

void Connection::fail_and_destroy() {
    set_state(IceCandidatePairState::FAILED);
    destroy();
}

void Connection::print_pings_since_last_response(std::string* s, size_t max) {
    std::ostringstream oss;
    oss << std::boolalpha;
    if (_pings_since_last_response.size() > max) {
        for (size_t i = 0; i < max; i++) {
            const SentPing& ping = _pings_since_last_response[i];
            oss << rtcbase::hex_encode(ping.id) << " ";
        }
        oss << "... " << (_pings_since_last_response.size() - max) << " more";
    } else {
        for (const SentPing& ping : _pings_since_last_response) {
            oss << rtcbase::hex_encode(ping.id) << " ";
        }
    }
    *s = oss.str();
}

bool Connection::rtt_converged() const {
    return _rtt_samples > (RTT_RATIO + 1);
}

bool Connection::missing_responses(int64_t now) const {
    if (_pings_since_last_response.empty()) {
        return false;
    }

    int64_t waiting = now - _pings_since_last_response[0].sent_time;
    return waiting > 2 * rtt();
}

void Connection::maybe_update_local_candidate(ConnectionRequest* request,
        StunMessage* response) 
{
    // RFC 5245
    // The agent checks the mapped address from the STUN response.  If the
    // transport address does not match any of the local candidates that the
    // agent knows about, the mapped address represents a new candidate -- a
    // peer reflexive candidate.
    const StunAddressAttribute* addr =
        response->get_address(STUN_ATTR_XOR_MAPPED_ADDRESS);
    if (!addr) {
        LOG(LS_WARNING) << "Connection::OnConnectionRequestResponse - "
            << "No MAPPED-ADDRESS or XOR-MAPPED-ADDRESS found in the "
            << "stun response message";
        return;
    }

    for (size_t i = 0; i < _port->candidates().size(); ++i) {
        if (_port->candidates()[i].address() == addr->get_address()) {
            if (_local_candidate_index != i) {
                LOG_J(LS_TRACE, this) << "Updating local candidate type to srflx.";
                _local_candidate_index = i;
                // SignalStateChange to force a re-sort in P2PTransportChannel as this
                // Connection's local candidate has changed.
                signal_state_change(this);
            }
            return;
        }
    }
    
    // RFC 5245
    // Its priority is set equal to the value of the PRIORITY attribute
    // in the Binding request.
    const StunUInt32Attribute* priority_attr =
        request->msg()->get_uint32(STUN_ATTR_PRIORITY);
    if (!priority_attr) {
        LOG_J(LS_WARNING, this) << "Connection::OnConnectionRequestResponse - "
            << "No STUN_ATTR_PRIORITY found in the "
            << "stun response message";
        return;
    }
    const uint32_t priority = priority_attr->value();
    std::string id = rtcbase::create_random_string(8);

    Candidate new_local_candidate;
    new_local_candidate.set_id(id);
    new_local_candidate.set_component(local_candidate().component());
    new_local_candidate.set_type(PRFLX_PORT_TYPE);
    new_local_candidate.set_protocol(local_candidate().protocol());
    new_local_candidate.set_address(addr->get_address());
    new_local_candidate.set_priority(priority);
    new_local_candidate.set_username(local_candidate().username());
    new_local_candidate.set_password(local_candidate().password());
    new_local_candidate.set_network_name(local_candidate().network_name());
    new_local_candidate.set_network_type(local_candidate().network_type());
    new_local_candidate.set_related_address(local_candidate().address());
    new_local_candidate.set_generation(local_candidate().generation());
    new_local_candidate.set_foundation(compute_foundation(
                PRFLX_PORT_TYPE, local_candidate().protocol(),
                local_candidate().relay_protocol(), local_candidate().address()));
    new_local_candidate.set_network_id(local_candidate().network_id());
    new_local_candidate.set_network_cost(local_candidate().network_cost());

    // Change the local candidate of this Connection to the new prflx candidate.
    LOG_J(LS_TRACE, this) << "Updating local candidate type to prflx.";
    _local_candidate_index = _port->add_prflx_candidate(new_local_candidate);

    // SignalStateChange to force a re-sort in P2PTransportChannel as this
    // Connection's local candidate has changed.
    signal_state_change(this);
}

///////////////// ProxyConnection ///////////////////
ProxyConnection::ProxyConnection(Port* port,
        size_t index,
        const Candidate& remote_candidate)
    : Connection(port, index, remote_candidate) 
{

}

int ProxyConnection::send(const void* data, size_t size,
        const rtcbase::PacketOptions& options) 
{
    int sent = _port->send_to(data, size, _remote_candidate.address(),
            options, true);
    if (sent <= 0) {
        _error = _port->get_error();
    } 
    return sent;
}

} // namespace ice 


