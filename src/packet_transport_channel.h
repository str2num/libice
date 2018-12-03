/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file packet_transport_channel.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_PACKET_TRANSPORT_CHANNEL_H_
#define  __ICE_PACKET_TRANSPORT_CHANNEL_H_

#include <rtcbase/async_packet_socket.h>
#include <rtcbase/sigslot.h>

namespace ice {

class PacketTransportChannel : public rtcbase::HasSlots<> {
public:
    virtual const std::string& transport_name() const = 0;
    
    virtual int component() const = 0;

    // The transport has been established.
    virtual bool writable() const = 0;

    // The transport has received a packet in the last X milliseconds, here X is
    // configured by each implementation.
    virtual bool receiving() const = 0;

    // Attempts to send the given packet.
    // The return value is < 0 on failure. The return value in failure case is not
    // descriptive. Depending on failure cause and implementation details
    // GetError() returns an descriptive errno.h error value.
    // This mimics posix socket send() or sendto() behavior.
    // TODO(johan): Reliable, meaningful, consistent error codes for all
    // implementations would be nice.
    // TODO(johan): Remove the default argument once channel code is updated.
    virtual int send_packet(const char* data,
            size_t len,
            const rtcbase::PacketOptions& options,
            int flags = 0) = 0;
    
    // Sets a socket option. Note that not all options are
    // supported by all transport types.
    virtual int set_option(rtcbase::Socket::Option opt, int value) = 0;
    
    virtual bool get_option(rtcbase::Socket::Option opt, int* value) = 0;

    // Returns the most recent error that occurred on this channel.
    virtual int get_error() = 0;

    // Emitted when the writable state, represented by |writable()|, changes.
    rtcbase::Signal1<PacketTransportChannel*> signal_writable_state;

    //  Emitted when the PacketTransportInternal is ready to send packets. "Ready
    //  to send" is more sensitive than the writable state; a transport may be
    //  writable, but temporarily not able to send packets. For example, the
    //  underlying transport's socket buffer may be full, as indicated by
    //  SendPacket's return code and/or GetError.
    rtcbase::Signal1<PacketTransportChannel*> signal_ready_to_send;

    // Emitted when receiving state changes to true.
    rtcbase::Signal1<PacketTransportChannel*> signal_receiving_state;

    // Signalled each time a packet is received on this channel.
    rtcbase::Signal5<PacketTransportChannel*,
        const char*, 
        size_t, 
        const rtcbase::PacketTime&, 
        int> signal_read_packet;

    /*
    // Signalled each time a packet is sent on this channel.
    rtcbase::Signal2<PacketTransportInternal*, const rtc::SentPacket&>
        SignalSentPacket;

    // Signalled when the current network route has changed.
    sigslot::signal1<rtc::Optional<rtc::NetworkRoute>> SignalNetworkRouteChanged;      
    */

protected:
    PacketTransportChannel() = default;
    virtual ~PacketTransportChannel() = default;
};

} // namespace ice

#endif  //__ICE_PACKET_TRANSPORT_INTERNAL_H_


