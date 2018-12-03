/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun_port.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <rtcbase/random.h>
#include <rtcbase/ipaddress.h>
#include <rtcbase/logging.h>
#include <rtcbase/net_helpers.h>

#include "ice_common.h"
#include "port_allocator.h"

#include "stun_port.h"

namespace ice {

UDPPort::UDPPort(PacketSocketFactory* factory,
        rtcbase::Network* network,
        rtcbase::AsyncPacketSocket* socket,
        const std::string& username,
        const std::string& password,
        const std::string& origin,
        bool emit_local_for_anyaddress)
    : Port(HOST_PORT_TYPE,
            factory,
            network,
            socket->get_local_address().ipaddr(),
            username,
            password),
    _socket(socket),
    _error(0),
    _ready(false),
    _emit_local_for_anyaddress(emit_local_for_anyaddress) 
{
    (void)origin;
}

UDPPort::~UDPPort() {}

void UDPPort::prepare_address() {
    if (_socket->get_state() == rtcbase::AsyncPacketSocket::STATE_BOUND) {
        on_local_address_ready(_socket, _socket->get_local_address());
    }
}

Connection* UDPPort::create_connection(const Candidate& address,
        CandidateOrigin origin) 
{
    (void)origin;

    if (!supports_protocol(address.protocol())) {
        return NULL;
    }
    
    if (!is_compatible_address(address.address())) {
        return NULL;
    }
    
    if (shared_socket() && candidates()[0].type() != HOST_PORT_TYPE) {
        return NULL;
    }
    
    Connection* conn = new ProxyConnection(this, 0, address);
    add_or_replace_connection(conn);
    return conn;
}

int UDPPort::send_to(const void* data, size_t size,
        const rtcbase::SocketAddress& addr,
        const rtcbase::PacketOptions& options,
        bool payload) 
{
    (void)payload;
    int sent = _socket->send_to(data, size, addr, options);
    if (sent < 0) {
        _error = _socket->get_error();
        LOG_J(LS_WARNING, this) << "UDP send of " << size
            << " bytes failed with error " << _error;
    }
    return sent;
}

int UDPPort::set_option(rtcbase::Socket::Option opt, int value) {
    return _socket->set_option(opt, value);
}

int UDPPort::get_option(rtcbase::Socket::Option opt, int* value) {
    return _socket->get_option(opt, value);
}

int UDPPort::get_error() {
    return _error;
}

bool UDPPort::handle_incoming_packet(
        rtcbase::AsyncPacketSocket* socket, const char* data, size_t size,
        const rtcbase::SocketAddress& remote_addr,
        const rtcbase::PacketTime& packet_time) 
{
    // All packets given to UDP port will be consumed.
    on_read_packet(socket, data, size, remote_addr, packet_time);
    return true;
}

bool UDPPort::supports_protocol(const std::string& protocol) const {
    return protocol == UDP_PROTOCOL_NAME;
}

void UDPPort::on_local_address_ready(rtcbase::AsyncPacketSocket* socket,
        const rtcbase::SocketAddress& address) 
{
    (void)socket;

    // When adapter enumeration is disabled and binding to the any address, the
    // default local address will be issued as a candidate instead if
    // |emit_local_for_anyaddress| is true. This is to allow connectivity for
    // applications which absolutely requires a HOST candidate.
    rtcbase::SocketAddress addr = address;
    
    // If MaybeSetDefaultLocalAddress fails, we keep the "any" IP so that at
    // least the port is listening.
    //maybe_set_default_local_address(&addr);
    
    add_address(addr, addr, rtcbase::SocketAddress(), UDP_PROTOCOL_NAME, "", "",
            HOST_PORT_TYPE, ICE_TYPE_PREFERENCE_HOST, 0, false);
    maybe_prepare_stun_candidate();
}

void UDPPort::on_read_packet(rtcbase::AsyncPacketSocket* socket,
        const char* data,
        size_t size,
        const rtcbase::SocketAddress& remote_addr,
        const rtcbase::PacketTime& packet_time) 
{
    if (socket != _socket || remote_addr.is_unresolved_IP()) {
        return;
    }

    if (Connection* conn = get_connection(remote_addr)) {
        conn->on_read_packet(data, size, packet_time);
    } else {
        Port::on_read_packet(data, size, remote_addr, PROTO_UDP);
    }
}

void UDPPort::maybe_prepare_stun_candidate() {
    // Sending binding request to the STUN server if address is available to
    // prepare STUN candidate.
    if (!_server_addresses.empty()) {
        //send_stun_binding_requests();
    } else {
        // Port is done allocating candidates.
        maybe_set_port_complete_or_error();
    }
}

void UDPPort::maybe_set_port_complete_or_error() {
    if (_ready) {
        return;
    }
     
    // Setting ready status.
    _ready = true;
    signal_port_complete(this);
}

} // namespace ice


