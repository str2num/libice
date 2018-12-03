/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_PORT_H_
#define  __ICE_PORT_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <rtcbase/log_trace_id.h>
#include <rtcbase/network.h>
#include <rtcbase/sigslot.h>
#include <rtcbase/socket_address.h>
#include <rtcbase/async_packet_socket.h>
#include <rtcbase/memcheck.h>

#include "candidate.h"
#include "candidate_pair_interface.h"
#include "packet_socket_factory.h"
#include "port_interface.h"
#include "stun.h"
#include "stun_request.h"

namespace ice {

class Connection;
class ConnectionRequest;

extern const char HOST_PORT_TYPE[];
extern const char SRFLX_PORT_TYPE[];
extern const char PRFLX_PORT_TYPE[];
extern const char RELAY_PORT_TYPE[];

extern const char UDP_PROTOCOL_NAME[];
extern const char TCP_PROTOCOL_NAME[];
extern const char SSLTCP_PROTOCOL_NAME[];

// RFC 6544, TCP candidate encoding rules.
extern const int DISCARD_PORT;
extern const char TCPTYPE_ACTIVE_STR[];
extern const char TCPTYPE_PASSIVE_STR[];
extern const char TCPTYPE_SIMOPEN_STR[];

enum IcePriorityValue {
    // The reason we are choosing Relay preference 2 is because, we can run
    // Relay from client to server on UDP/TCP/TLS. To distinguish the transport
    // protocol, we prefer UDP over TCP over TLS.
    // For UDP ICE_TYPE_PREFERENCE_RELAY will be 2.
    // For TCP ICE_TYPE_PREFERENCE_RELAY will be 1.
    // For TLS ICE_TYPE_PREFERENCE_RELAY will be 0.
    // Check turnport.cc for setting these values.
    ICE_TYPE_PREFERENCE_RELAY = 2,
    ICE_TYPE_PREFERENCE_PRFLX_TCP = 80,
    ICE_TYPE_PREFERENCE_HOST_TCP = 90,
    ICE_TYPE_PREFERENCE_SRFLX = 100,
    ICE_TYPE_PREFERENCE_PRFLX = 110,
    ICE_TYPE_PREFERENCE_HOST = 126
};

// States are from RFC 5245. http://tools.ietf.org/html/rfc5245#section-5.7.4
enum class IceCandidatePairState {
    WAITING = 0,  // Check has not been performed, Waiting pair on CL.
    INPROGRESS,   // Check has been sent, transaction is in progress.
    SUCCEEDED,    // Check already done, produced a successful result.
    FAILED,        // Check for this connection failed.
    // According to spec there should also be a frozen state, but nothing is ever
    // frozen because we have not implemented ICE freezing logic.
};

const char* proto_to_string(ProtocolType proto);
bool string_to_proto(const char* value, ProtocolType* proto);

typedef std::set<rtcbase::SocketAddress> ServerAddresses;

// Represents a local communication mechanism that can be used to create
// connections to similar mechanisms of the other client.  Subclasses of this
// one add support for specific mechanisms like local UDP ports.
class Port : public PortInterface, 
             public rtcbase::HasSlots<>, 
             public rtcbase::LogTraceId,
             public rtcbase::MemCheck
{
public:
    // INIT: The state when a port is just created.
    // KEEP_ALIVE_UNTIL_PRUNED: A port should not be destroyed even if no
    // connection is using it.
    // PRUNED: It will be destroyed if no connection is using it for a period of
    // 30 seconds.
    enum class State { INIT, KEEP_ALIVE_UNTIL_PRUNED, PRUNED };
    Port(const std::string& type,
            PacketSocketFactory* factory,
            rtcbase::Network* network,
            const rtcbase::IPAddress& ip,
            const std::string& username_fragment,
            const std::string& password);
    Port(const std::string& type,
            PacketSocketFactory* factory,
            rtcbase::Network* network,
            const rtcbase::IPAddress& ip,
            uint16_t min_port,
            uint16_t max_port,
            const std::string& username_fragment,
            const std::string& password);
    virtual ~Port();
        
    virtual const std::string& type() const { return _type; }
    virtual rtcbase::Network* network() const { return _network; }
    
    // Methods to set/get ICE role and tiebreaker values.
    IceRole get_ice_role() const { return _ice_role; }
    void set_ice_role(IceRole role) { _ice_role = role; }
    
    void set_ice_tiebreaker(uint64_t tiebreaker) { _tiebreaker = tiebreaker; }
    uint64_t ice_tiebreaker() const { return _tiebreaker; }

    virtual bool shared_socket() const { return _shared_socket; }
    void reset_shared_socket() { _shared_socket = false; }
    
    // Should not destroy the port even if no connection is using it. Called when
    // a port is ready to use.
    void keep_alive_until_pruned();

    const std::string& content_name() const { return _content_name; }
    void set_content_name(const std::string& content_name) {
        _content_name = content_name;
    }

    int component() const { return _component; }
    void set_component(int component) { _component = component; }
    
    // Identifies the generation that this port was created in.
    uint32_t generation() const { return _generation; }
    void set_generation(uint32_t generation) { _generation = generation; }
    
    const std::string username_fragment() const;
    const std::string& password() const { return _password; }
    
    // Fired when candidates are discovered by the port. When all candidates
    // are discovered that belong to port SignalAddressReady is fired.
    rtcbase::Signal2<Port*, const Candidate&> signal_candidate_ready;
    
    // Provides all of the above information in one handy object.
    virtual const std::vector<Candidate>& candidates() const {
        return _candidates;
    }
    
    // SignalPortComplete is sent when port completes the task of candidates
    // allocation.
    rtcbase::Signal1<Port*> signal_port_complete;
    
    // This signal sent when port fails to allocate candidates and this port
    // can't be used in establishing the connections. When port is in shared mode
    // and port fails to allocate one of the candidates, port shouldn't send
    // this signal as other candidates might be usefull in establishing the
    // connection.
    rtcbase::Signal1<Port*> signal_port_error;

    // Returns a map containing all of the connections of this port, keyed by the
    // remote address.
    typedef std::map<rtcbase::SocketAddress, Connection*> AddressMap;
    const AddressMap& connections() { return _connections; }

    // Returns the connection to the given address or NULL if none exists.
    virtual Connection* get_connection(const rtcbase::SocketAddress& remote_addr);
    
    // Called each time a connection is created.
    rtcbase::Signal2<Port*, Connection*> signal_connection_created;
    
    // In a shared socket mode each port which shares the socket will decide
    // to accept the packet based on the |remote_addr|. Currently only UDP
    // port implemented this method.
    // TODO(mallinath) - Make it pure virtual.
    virtual bool handle_incoming_packet(rtcbase::AsyncPacketSocket* socket,
            const char* data,
            size_t size,
            const rtcbase::SocketAddress& remote_addr,
            const rtcbase::PacketTime& packet_time) = 0;

    // Sends a response message (normal or error) to the given request.  One of
    // these methods should be called as a response to SignalUnknownAddress.
    // NOTE: You MUST call CreateConnection BEFORE SendBindingResponse.
    virtual void send_binding_response(StunMessage* request,
            const rtcbase::SocketAddress& addr); 
    virtual void send_binding_error_response(
            StunMessage* request, const rtcbase::SocketAddress& addr,
            int error_code, const std::string& reason);

    virtual std::string to_string() const;
    const rtcbase::IPAddress& ip() const { return _ip; }
    
    // This method will return local and remote username fragements from the
    // stun username attribute if present.
    bool parse_stun_username(const StunMessage* stun_msg,
            std::string* local_username,
            std::string* remote_username) const;
    void create_stun_username(const std::string& remote_username,
            std::string* stun_username_attr_str) const;
    
    bool maybe_ice_role_conflict(const rtcbase::SocketAddress& addr,
            IceMessage* stun_msg,
            const std::string& remote_ufrag); 
    
    // Called when the Connection discovers a local peer reflexive candidate.
    // Returns the index of the new local candidate.
    size_t add_prflx_candidate(const Candidate& local);

    int16_t network_cost() const { return _network_cost; }
    
    rtcbase::EventLoop* event_loop() { return _factory->event_loop(); }

protected:
    void add_address(const rtcbase::SocketAddress& address,
            const rtcbase::SocketAddress& base_address,
            const rtcbase::SocketAddress& related_address,
            const std::string& protocol,
            const std::string& relay_protocol,
            const std::string& tcptype,
            const std::string& type,
            uint32_t type_preference,
            uint32_t relay_preference,
            bool last);
    
    // Adds the given connection to the map keyed by the remote candidate address.
    // If an existing connection has the same address, the existing one will be
    // replaced and destroyed.
    void add_or_replace_connection(Connection* conn);
    
    // Called when a packet is received from an unknown address that is not
    // currently a connection.  If this is an authenticated STUN binding request,
    // then we will signal the client.
    void on_read_packet(const char* data, size_t size,
            const rtcbase::SocketAddress& addr,
            ProtocolType proto); 

    // If the given data comprises a complete and correct STUN message then the
    // return value is true, otherwise false. If the message username corresponds
    // with this port's username fragment, msg will contain the parsed STUN
    // message.  Otherwise, the function may send a STUN response internally.
    // remote_username contains the remote fragment of the STUN username.
    bool get_stun_message(const char* data,
            size_t size,
            const rtcbase::SocketAddress& addr,
            std::unique_ptr<IceMessage>* out_msg,
            std::string* out_username);

    // Checks if the address in addr is compatible with the port's ip.
    bool is_compatible_address(const rtcbase::SocketAddress& addr);
    
    // Returns default DSCP value.
    rtcbase::DiffServCodePoint default_dscp_value() const {
        // No change from what MediaChannel set.
        return rtcbase::DSCP_NO_CHANGE;
    }
    
    // Extra work to be done in subclasses when a connection is destroyed.
    virtual void handle_connection_destroyed(Connection* conn) { (void)conn; }

private:
    void construct();
    // Called when one of our connections deletes itself.
    void on_connection_destroyed(Connection* conn);

private:
    PacketSocketFactory* _factory;
    std::string _type;
    rtcbase::Network* _network;
    rtcbase::IPAddress _ip;
    uint16_t _min_port;
    uint16_t _max_port;
    std::string _content_name;
    int _component;
    uint32_t _generation;
    // In order to establish a connection to this Port (so that real data can be
    // sent through), the other side must send us a STUN binding request that is
    // authenticated with this username_fragment and password.
    // PortAllocatorSession will provide these username_fragment and password.
    //
    // Note: we should always use username_fragment() instead of using
    // |ice_username_fragment_| directly. For the details see the comment on
    // username_fragment().
    std::string _ice_username_fragment;
    std::string _password;
    std::vector<Candidate> _candidates;
    AddressMap _connections;
    bool _enable_port_packets;
    IceRole _ice_role;
    uint64_t _tiebreaker;
    bool _shared_socket;
    
    // A virtual cost perceived by the user, usually based on the network type
    // (WiFi. vs. Cellular). It takes precedence over the priority when
    // comparing two connections.
    uint16_t _network_cost;
    State _state = State::INIT;
    
    friend class Connection;
};

// Represents a communication link between a port on the local client and a
// port on the remote client.
class Connection : public CandidatePairInterface,
                   public rtcbase::HasSlots<>,
                   public rtcbase::LogTraceId,
                   public rtcbase::MemCheck
{
public:
    struct SentPing {
        SentPing(const std::string id, int64_t sent_time, uint32_t nomination)
            : id(id), sent_time(sent_time), nomination(nomination) {}

        std::string id;
        int64_t sent_time;
        uint32_t nomination;
    };
 
    virtual ~Connection();
    
    // The local port where this connection sends and receives packets.
    Port* port() { return _port; }
    const Port* port() const { return _port; }

    // Implementation of virtual methods in CandidatePairInterface.
    // Returns the description of the local port
    virtual const Candidate& local_candidate() const;
    // Returns the description of the remote port to which we communicate.
    virtual const Candidate& remote_candidate() const;
    
    // Returns the pair priority.
    uint64_t priority() const;

    enum WriteState {
        STATE_WRITABLE          = 0,  // we have received ping responses recently
        STATE_WRITE_UNRELIABLE  = 1,  // we have had a few ping failures
        STATE_WRITE_INIT        = 2,  // we have yet to receive a ping response
        STATE_WRITE_TIMEOUT     = 3,  // we have had a large number of ping failures
    };

    WriteState write_state() const { return _write_state; }
    bool writable() const { return _write_state == STATE_WRITABLE; }
    bool receiving() const { return _receiving; }

    // Determines whether the connection has finished connecting.  This can only
    // be false for TCP connections.
    bool connected() const { return _connected; }
    bool weak() const { return !(writable() && receiving() && connected()); }
    bool active() const {
        return _write_state != STATE_WRITE_TIMEOUT;
    }

    // A connection is dead if it can be safely deleted.
    bool dead(int64_t now) const;
    
    // Estimate of the round-trip time over this connection.
    int rtt() const { return _rtt; }

    rtcbase::Signal1<Connection*> signal_state_change;
    
    // Sent when the connection has decided that it is no longer of value.  It
    // will delete itself immediately after this call.
    rtcbase::Signal1<Connection*> signal_destroyed;
    
    // The connection can send and receive packets asynchronously.  This matches
    // the interface of AsyncPacketSocket, which may use UDP or TCP under the
    // covers.
    virtual int send(const void* data, size_t size,
            const rtcbase::PacketOptions& options) = 0;

    // Error if Send() returns < 0
    virtual int get_error() = 0;
    
    rtcbase::Signal4<Connection*, const char*, size_t, const rtcbase::PacketTime&>
        signal_read_packet;

    // Called when a packet is received on this connection.
    void on_read_packet(const char* data, size_t size,
            const rtcbase::PacketTime& packet_time);
    
    // Called when a connection is determined to be no longer useful to us.  We
    // still keep it around in case the other side wants to use it.  But we can
    // safely stop pinging on it and we can allow it to time out if the other
    // side stops using it as well.
    bool pruned() const { return _pruned; }
    void prune();

    bool use_candidate_attr() const { return _use_candidate_attr; }
    void set_use_candidate_attr(bool enable);

    void set_nomination(uint32_t value) { _nomination = value; }    
 
    uint32_t remote_nomination() const { return _remote_nomination; }
    bool nominated() const { return _remote_nomination > 0; }
    // Public for unit tests.
    void set_remote_nomination(uint32_t remote_nomination) {
        _remote_nomination = remote_nomination;
    } 
    // Public for unit tests.
    uint32_t acked_nomination() const { return _acked_nomination; }    
    
    void set_remote_ice_mode(IceMode mode) {
        _remote_ice_mode = mode;
    }

    void set_receiving_timeout(int64_t receiving_timeout_ms) {
        _receiving_timeout = receiving_timeout_ms;
    }
    
    // Makes the connection go away.
    void destroy();
    
    // Makes the connection go away, in a failed state.
    void fail_and_destroy();

    // Checks that the state of this connection is up-to-date.  The argument is
    // the current time, which is compared against various timeouts.
    void update_state(int64_t now);
    
    // Called when this connection should try checking writability again.
    int64_t last_ping_sent() const { return _last_ping_sent; }
    void ping(int64_t now);
    void received_ping_response(int rtt, const std::string& request_id);
    int64_t last_ping_response_received() const {
        return _last_ping_response_received;
    }
    // Used to check if any STUN ping response has been received.
    int rtt_samples() const { return _rtt_samples; }
    
    // Called whenever a valid ping is received on this connection.  This is
    // public because the connection intercepts the first ping for us.
    int64_t last_ping_received() const { return _last_ping_received; }
    void received_ping();
    // Handles the binding request; sends a response if this is a valid request.
    void handle_binding_request(IceMessage* msg);
 
    int64_t last_data_received() const { return _last_data_received; }

    std::string to_debug_id() const;
    std::string to_string();
    // Prints pings_since_last_response_ into a string.
    void print_pings_since_last_response(std::string* pings, size_t max);
    
    // The following two methods are only used for logging in ToString above, and
    // this flag is set true by P2PTransportChannel for its selected candidate
    // pair.
    bool selected() const { return _selected; }
    void set_selected(bool selected) { _selected = selected; }

    // This signal will be fired if this connection is nominated by the
    // controlling side.
    rtcbase::Signal1<Connection*> signal_nominated;
    
    // Invoked when Connection receives STUN error response with 487 code.
    void handle_role_conflict_from_peer();

    IceCandidatePairState state() const { return _state; }
    
    int num_pings_sent() const { return _num_pings_sent; }

    uint32_t compute_network_cost() const;
    
    // Update the ICE password and/or generation of the remote candidate if a
    // ufrag in |remote_ice_parameters| matches the candidate's ufrag, and the
    // candidate's password and/or ufrag has not been set.
    // |remote_ice_parameters| should be a list of known ICE parameters ordered
    // by generation.
    void maybe_set_remote_ice_credentials_and_generation(
            const IceParameters& params,
            int generation);
    
    // If |_remote_candidate| is peer reflexive and is equivalent to
    // |new_candidate| except the type, update |_remote_candidate| to
    // |new_candidate|.
    void maybe_update_peer_reflexive_candidate(const Candidate& new_candidate);

    // Returns the last received time of any data, stun request, or stun
    // response in milliseconds
    int64_t last_received() const;
    // Returns the last time when the connection changed its receiving state.
    int64_t receiving_unchanged_since() const {
        return _receiving_unchanged_since;
    }     
    
    bool stable(int64_t now) const;
    
protected:
    // Constructs a new connection to the given remote port.
    Connection(Port* port, size_t index, const Candidate& candidate);
    
    // Called back when StunRequestManager has a stun packet to send
    void on_send_stun_packet(const void* data, size_t size, StunRequest* req);
    
    // Callbacks from ConnectionRequest
    virtual void on_connection_request_response(ConnectionRequest* req,
            StunMessage* response);
    void on_connection_request_error_response(ConnectionRequest* req,
            StunMessage* response);
    void on_connection_request_timeout(ConnectionRequest* req);
    void on_connection_request_sent(ConnectionRequest* req);

    bool rtt_converged() const;
    
    // If the response is not received within 2 * RTT, the response is assumed to
    // be missing.
    bool missing_responses(int64_t now) const;

    // Changes the state and signals if necessary.
    void set_write_state(WriteState value);
    void update_receiving(int64_t now);
    void set_state(IceCandidatePairState state);

    uint32_t nomination() const { return _nomination; }
     
private:
    // Update the local candidate based on the mapped address attribute.
    // If the local candidate changed, fires SignalStateChange.
    void maybe_update_local_candidate(ConnectionRequest* request,
            StunMessage* response); 

protected:
    Port* _port;
    size_t _local_candidate_index;
    Candidate _remote_candidate;

private:
    WriteState _write_state;
    bool _receiving;
    bool _connected;
    bool _pruned;
    bool _selected = false;
    // By default |use_candidate_attr_| flag will be true,
    // as we will be using aggressive nomination.
    // But when peer is ice-lite, this flag "must" be initialized to false and
    // turn on when connection becomes "best connection".
    bool _use_candidate_attr; 
    // Used by the controlling side to indicate that this connection will be
    // selected for transmission if the peer supports ICE-renomination when this
    // value is positive. A larger-value indicates that a connection is nominated
    // later and should be selected by the controlled side with higher precedence.
    // A zero-value indicates not nominating this connection.
    uint32_t _nomination = 0;
    // The last nomination that has been acknowledged.
    uint32_t _acked_nomination = 0; 
    // Used by the controlled side to remember the nomination value received from
    // the controlling side. When the peer does not support ICE re-nomination,
    // its value will be 1 if the connection has been nominated.
    uint32_t _remote_nomination = 0;
    
    IceMode _remote_ice_mode;
    StunRequestManager _requests;
    int _rtt;
    int _rtt_samples = 0;
    int64_t _last_ping_sent;      // last time we sent a ping to the other side
    int64_t _last_ping_received;  // last time we received a ping from the other side
    int64_t _last_data_received;
    int64_t _last_ping_response_received;
    int64_t _receiving_unchanged_since = 0;
    std::vector<SentPing> _pings_since_last_response;  

    IceCandidatePairState _state;
    // Time duration to switch from receiving to not receiving.
    int _receiving_timeout;
    int64_t _time_created_ms;
    int _num_pings_sent = 0;
    
    friend class Port;
    friend class ConnectionRequest;
};

// ProxyConnection defers all the interesting work to the port.
class ProxyConnection : public Connection {
public:
    ProxyConnection(Port* port, size_t index, const Candidate& remote_candidate);

    int send(const void* data,
            size_t size,
            const rtcbase::PacketOptions& options) override;
    int get_error() override { return _error; }
    
private:
    int _error = 0;
};

} // namespace ice

#endif  //__ICE_PORT_H_


