/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file packet_socket_factory.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_PACKET_SOCKET_FACTORY_H_
#define  __ICE_PACKET_SOCKET_FACTORY_H_

#include <rtcbase/event_loop.h>
#include <rtcbase/constructor_magic.h>
#include <rtcbase/socket_address.h>

namespace rtcbase {
class AsyncPacketSocket;
}

namespace ice {

class PacketSocketFactory {
public:
    PacketSocketFactory() {}
    virtual ~PacketSocketFactory() {}

    virtual rtcbase::AsyncPacketSocket* create_udp_socket(const rtcbase::SocketAddress& address,
            uint16_t min_port,
            uint16_t max_port) = 0;
    virtual rtcbase::EventLoop* event_loop() = 0;

private:
    RTC_DISALLOW_COPY_AND_ASSIGN(PacketSocketFactory);
};

} // namespace ice

#endif  //__ICE_PACKET_SOCKET_FACTORY_H_


