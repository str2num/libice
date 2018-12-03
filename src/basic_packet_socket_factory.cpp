/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file basic_packet_socket_factory.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <rtcbase/logging.h>
#include <rtcbase/physical_socket_server.h>
#include <rtcbase/async_udp_socket.h>

#include "ice_common.h"
#include "basic_packet_socket_factory.h"

namespace ice {

BasicPacketSocketFactory::BasicPacketSocketFactory() :
    rtcbase::MemCheck("BasicPacketSocketFactory"),
    _el(NULL), _socket_factory(NULL)
{
    construct();
}

BasicPacketSocketFactory::BasicPacketSocketFactory(rtcbase::EventLoop* el, 
        rtcbase::SocketFactory* socket_factory) :
    rtcbase::MemCheck("BasicPacketSocketFactory"),
    _el(el), _socket_factory(socket_factory)
{
    construct();
}

BasicPacketSocketFactory::~BasicPacketSocketFactory() {
}

void BasicPacketSocketFactory::construct() {
    if (!_socket_factory) {
        _internal_socket_factory.reset(new rtcbase::PhysicalSocketServer());
        _socket_factory = _internal_socket_factory.get();
    }
}

rtcbase::AsyncPacketSocket* BasicPacketSocketFactory::create_udp_socket(
        const rtcbase::SocketAddress& address,
        uint16_t min_port,
        uint16_t max_port) 
{
    if (!_el) {
        return NULL;
    }

    // UDP sockets are simple.
    rtcbase::AsyncSocket* socket =
        socket_factory()->create_async_socket(address.family(), SOCK_DGRAM);
    if (!socket) {
        return NULL;
    }
    
    if (bind_socket(socket, address, min_port, max_port) < 0) {
        LOG(LS_FATAL) << "UDP bind failed with error "
            << socket->get_error();
        delete socket;
        return NULL;
    }
    return new rtcbase::AsyncUDPSocket(_el, socket);
}

int BasicPacketSocketFactory::bind_socket(rtcbase::AsyncSocket* socket,
        const rtcbase::SocketAddress& local_address,
        uint16_t min_port,
        uint16_t max_port) 
{
    int ret = -1;
    if (min_port == 0 && max_port == 0) {
        // If there's no port range, let the OS pick a port for us.
        ret = socket->bind(local_address);
    } else {
        // Otherwise, try to find a port in the provided range.
        for (int port = min_port; ret < 0 && port <= max_port; ++port) {
            ret = socket->bind(rtcbase::SocketAddress(local_address.ipaddr(),
                        port));
        }
    }
    return ret;
}

rtcbase::SocketFactory* BasicPacketSocketFactory::socket_factory() {
    return _socket_factory;
}

} // namespace ice


