/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file basic_packet_socket_factory.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_BASIC_PACKET_SOCKET_FACTORY_H_
#define  __ICE_BASIC_PACKET_SOCKET_FACTORY_H_

#include <memory>

#include <rtcbase/event_loop.h>
#include <rtcbase/memcheck.h>
#include "packet_socket_factory.h"

namespace rtcbase {
class AsyncSocket;
class SocketFactory;
}

namespace ice {

class BasicPacketSocketFactory : public PacketSocketFactory, public rtcbase::MemCheck {
public:
    BasicPacketSocketFactory();
    BasicPacketSocketFactory(rtcbase::EventLoop* el, rtcbase::SocketFactory* socket_factory = NULL);
    ~BasicPacketSocketFactory() override;
    
    rtcbase::AsyncPacketSocket* create_udp_socket(const rtcbase::SocketAddress& local_address,
            uint16_t min_port,
            uint16_t max_port) override;
    
    rtcbase::EventLoop* event_loop() { return _el; }

private:
    void construct();
    int bind_socket(rtcbase::AsyncSocket* socket,
            const rtcbase::SocketAddress& local_address,
            uint16_t min_port,
            uint16_t max_port);
    rtcbase::SocketFactory* socket_factory();

private:
    rtcbase::EventLoop* _el;
    rtcbase::SocketFactory* _socket_factory;
    std::unique_ptr<rtcbase::SocketFactory> _internal_socket_factory;
};

} // namespace ice

#endif  //__ICE_BASIC_PACKET_SOCKET_FACTORY_H_


