/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun_port.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_STUN_PORT_H_
#define  __ICE_STUN_PORT_H_

#include <memory>
#include <string>

#include <rtcbase/async_packet_socket.h>

#include "port.h"

namespace ice {

// Communicates using the address on the outside of a NAT.
class UDPPort : public Port {
public:
    static UDPPort* create(PacketSocketFactory* factory,
            rtcbase::Network* network,
            rtcbase::AsyncPacketSocket* socket,
            const std::string& username,
            const std::string& password,
            const std::string& origin,
            bool emit_local_for_anyaddress) 
    {
        return new UDPPort(factory, network, socket, username,
                password, origin, emit_local_for_anyaddress);
    }

    virtual ~UDPPort();
    
    virtual void prepare_address() override;
    virtual Connection* create_connection(const Candidate& address,
            CandidateOrigin origin) override;

    virtual int set_option(rtcbase::Socket::Option opt, int value) override;
    virtual int get_option(rtcbase::Socket::Option opt, int* value) override;
    virtual int get_error() override;
    
    virtual bool handle_incoming_packet(
            rtcbase::AsyncPacketSocket* socket, const char* data, size_t size,
            const rtcbase::SocketAddress& remote_addr,
            const rtcbase::PacketTime& packet_time) override;

    virtual bool supports_protocol(const std::string& protocol) const override;

protected:
    UDPPort(PacketSocketFactory* factory,
            rtcbase::Network* network,
            rtcbase::AsyncPacketSocket* socket,
            const std::string& username,
            const std::string& password,
            const std::string& origin,
            bool emit_local_for_anyaddress);
 
    virtual int send_to(const void* data, size_t size,
            const rtcbase::SocketAddress& addr,
            const rtcbase::PacketOptions& options,
            bool payload);

    void on_local_address_ready(rtcbase::AsyncPacketSocket* socket,
            const rtcbase::SocketAddress& address);
    
    void on_read_packet(rtcbase::AsyncPacketSocket* socket,
            const char* data, size_t size,
            const rtcbase::SocketAddress& remote_addr,
            const rtcbase::PacketTime& packet_time);

    // This method will send STUN binding request if STUN server address is set.
    void maybe_prepare_stun_candidate();

private:
    // TODO(mallinaht) - Move this up to cricket::Port when SignalAddressReady is
    // changed to SignalPortReady.
    void maybe_set_port_complete_or_error();

private:
    ServerAddresses _server_addresses;
    rtcbase::AsyncPacketSocket* _socket;
    int _error;
    bool _ready;

    // This is true by default and false when
    // PORTALLOCATOR_DISABLE_DEFAULT_LOCAL_CANDIDATE is specified.
    bool _emit_local_for_anyaddress; 
};

} // namespace ice

#endif  //__ICE_STUN_PORT_H_


