/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port_interface.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_PORT_INTERFACE_H_
#define  __ICE_PORT_INTERFACE_H_

#include <string>

#include <rtcbase/async_packet_socket.h>
#include <rtcbase/socket_address.h>

#include "ice_common.h"

namespace ice {

class Connection;
class IceMessage;
class StunMessage;

enum ProtocolType {
    PROTO_UDP,
    PROTO_TCP,
    PROTO_SSLTCP,
    PROTO_LAST = PROTO_SSLTCP
};

// Defines the interface for a port, which represents a local communication
// mechanism that can be used to create connections to similar mechanisms of
// the other client. Various types of ports will implement this interface.
class PortInterface {
public:
    virtual ~PortInterface() {}

    //virtual const std::string& Type() const = 0;
    //virtual rtc::Network* Network() const = 0;

    // Methods to set/get ICE role and tiebreaker values.
    virtual void set_ice_role(IceRole role) = 0;
    virtual IceRole get_ice_role() const = 0;

    virtual void set_ice_tiebreaker(uint64_t tiebreaker) = 0;
    virtual uint64_t ice_tiebreaker() const = 0;

    //virtual bool SharedSocket() const = 0;

    virtual bool supports_protocol(const std::string& protocol) const = 0;

    // PrepareAddress will attempt to get an address for this port that other
    // clients can send to.  It may take some time before the address is ready.
    // Once it is ready, we will send SignalAddressReady.  If errors are
    // preventing the port from getting an address, it may send
    // SignalAddressError.
    virtual void prepare_address() = 0;

    // Returns the connection to the given address or NULL if none exists.
    virtual Connection* get_connection(const rtcbase::SocketAddress& remote_addr) = 0;

    // Creates a new connection to the given address.
    enum CandidateOrigin { ORIGIN_THIS_PORT, ORIGIN_OTHER_PORT, ORIGIN_MESSAGE };
    virtual Connection* create_connection(
            const Candidate& remote_candidate, CandidateOrigin origin) = 0;

    // Functions on the underlying socket(s).
    virtual int set_option(rtcbase::Socket::Option opt, int value) = 0;
    virtual int get_option(rtcbase::Socket::Option opt, int* value) = 0;
    virtual int get_error() = 0;

    //virtual ProtocolType GetProtocol() const = 0;

    //virtual const std::vector<Candidate>& Candidates() const = 0;

    // Sends the given packet to the given address, provided that the address is
    // that of a connection or an address that has sent to us already.
    virtual int send_to(const void* data, size_t size,
            const rtcbase::SocketAddress& addr,
            const rtcbase::PacketOptions& options, bool payload) = 0;

    // Indicates that we received a successful STUN binding request from an
    // address that doesn't correspond to any current connection.  To turn this
    // into a real connection, call CreateConnection.
    rtcbase::Signal6<PortInterface*, const rtcbase::SocketAddress&,
        ProtocolType, IceMessage*, const std::string&,
        bool> signal_unknown_address;

    // Sends a response message (normal or error) to the given request.  One of
    // these methods should be called as a response to SignalUnknownAddress.
    // NOTE: You MUST call CreateConnection BEFORE SendBindingResponse.
    //virtual void send_binding_response(StunMessage* request,
      //      const rtcbase::SocketAddress& addr) = 0;
    virtual void send_binding_error_response(
            StunMessage* request, const rtcbase::SocketAddress& addr,
            int error_code, const std::string& reason) = 0;
    
    // Signaled when this port decides to delete itself because it no longer has
    // any usefulness.
    //sigslot::signal1<PortInterface*> SignalDestroyed;

    // Signaled when Port discovers ice role conflict with the peer.
    rtcbase::Signal1<PortInterface*> signal_role_conflict;
    
    /*
    // Normally, packets arrive through a connection (or they result signaling of
    // unknown address).  Calling this method turns off delivery of packets
    // through their respective connection and instead delivers every packet
    // through this port.
    virtual void EnablePortPackets() = 0;
    sigslot::signal4<PortInterface*, const char*, size_t,
        const rtc::SocketAddress&> SignalReadPacket;

    // Emitted each time a packet is sent on this port.
    sigslot::signal1<const rtc::SentPacket&> SignalSentPacket;
    */

    virtual std::string to_string() const = 0;

protected:
    PortInterface() {}
};

} // namespace ice

#endif  //__ICE_PORT_INTERFACE_H_


