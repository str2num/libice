/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_STUN_H_
#define  __ICE_STUN_H_

// This file contains classes for dealing with the STUN protocol, as specified
// in RFC 5389, and its descendants.

#include <string>
#include <vector>

#include <rtcbase/basic_types.h>
#include <rtcbase/byte_buffer.h>
#include <rtcbase/socket_address.h>
#include <rtcbase/memcheck.h>

namespace ice {

// These are the types of STUN messages defined in RFC 5389.
enum StunMessageType {
    STUN_BINDING_REQUEST                  = 0x0001,
    STUN_BINDING_INDICATION               = 0x0011,
    STUN_BINDING_RESPONSE                 = 0x0101,
    STUN_BINDING_ERROR_RESPONSE           = 0x0111,
};

// These are all known STUN attributes, defined in RFC 5389 and elsewhere.
// Next to each is the name of the class (T is StunTAttribute) that implements
// that type.
// RETRANSMIT_COUNT is the number of outstanding pings without a response at
// the time the packet is generated.
enum StunAttributeType {
    STUN_ATTR_MAPPED_ADDRESS              = 0x0001,  // Address
    STUN_ATTR_USERNAME                    = 0x0006,  // ByteString
    STUN_ATTR_MESSAGE_INTEGRITY           = 0x0008,  // ByteString, 20 bytes
    STUN_ATTR_ERROR_CODE                  = 0x0009,  // ErrorCode
    STUN_ATTR_UNKNOWN_ATTRIBUTES          = 0x000a,  // UInt16List
    STUN_ATTR_REALM                       = 0x0014,  // ByteString
    STUN_ATTR_NONCE                       = 0x0015,  // ByteString
    STUN_ATTR_XOR_MAPPED_ADDRESS          = 0x0020,  // XorAddress
    STUN_ATTR_SOFTWARE                    = 0x8022,  // ByteString
    STUN_ATTR_ALTERNATE_SERVER            = 0x8023,  // Address
    STUN_ATTR_FINGERPRINT                 = 0x8028,  // UInt32
    STUN_ATTR_ORIGIN                      = 0x802F,  // ByteString
    STUN_ATTR_RETRANSMIT_COUNT            = 0xFF00   // UInt32
};

// These are the types of the values associated with the attributes above.
// This allows us to perform some basic validation when reading or adding
// attributes. Note that these values are for our own use, and not defined in
// RFC 5389.
enum StunAttributeValueType {
    STUN_VALUE_UNKNOWN                    = 0,
    STUN_VALUE_ADDRESS                    = 1,
    STUN_VALUE_XOR_ADDRESS                = 2,
    STUN_VALUE_UINT32                     = 3,
    STUN_VALUE_UINT64                     = 4,
    STUN_VALUE_BYTE_STRING                = 5,
    STUN_VALUE_ERROR_CODE                 = 6,
    STUN_VALUE_UINT16_LIST                = 7
};

// These are the types of STUN addresses defined in RFC 5389.
enum StunAddressFamily {
    // NB: UNDEF is not part of the STUN spec.
    STUN_ADDRESS_UNDEF                    = 0,
    STUN_ADDRESS_IPV4                     = 1,
    STUN_ADDRESS_IPV6                     = 2
};

// These are the types of STUN error codes defined in RFC 5389.
enum StunErrorCode {
    STUN_ERROR_TRY_ALTERNATE              = 300,
    STUN_ERROR_BAD_REQUEST                = 400,
    STUN_ERROR_UNAUTHORIZED               = 401,
    STUN_ERROR_UNKNOWN_ATTRIBUTE          = 420,
    STUN_ERROR_STALE_CREDENTIALS          = 430,  // GICE only
    STUN_ERROR_STALE_NONCE                = 438,
    STUN_ERROR_SERVER_ERROR               = 500,
    STUN_ERROR_GLOBAL_FAILURE             = 600
};

// Strings for the error codes above.
extern const char STUN_ERROR_REASON_TRY_ALTERNATE_SERVER[];
extern const char STUN_ERROR_REASON_BAD_REQUEST[];
extern const char STUN_ERROR_REASON_UNAUTHORIZED[];
extern const char STUN_ERROR_REASON_UNKNOWN_ATTRIBUTE[];
extern const char STUN_ERROR_REASON_STALE_CREDENTIALS[];
extern const char STUN_ERROR_REASON_STALE_NONCE[];
extern const char STUN_ERROR_REASON_SERVER_ERROR[];

// The mask used to determine whether a STUN message is a request/response etc.
const uint32_t k_stun_type_mask = 0x0110;

// STUN Attribute header length.
const size_t k_stun_attribute_header_size = 4;

// Following values correspond to RFC5389.
const size_t k_stun_header_size = 20;
const size_t k_stun_transaction_id_offset = 8;
const size_t k_stun_transaction_id_length = 12;
const uint32_t k_stun_magic_cookie = 0x2112A442;
const size_t k_stun_magic_cookie_length = sizeof(k_stun_magic_cookie);

// Following value corresponds to an earlier version of STUN from
// RFC3489.
const size_t k_stun_legacy_transaction_id_length = 16;

// STUN Message Integrity HMAC length.
const size_t k_stun_message_integrity_size = 20;

class StunAttribute;
class StunAddressAttribute;
class StunXorAddressAttribute;
class StunUInt32Attribute;
class StunUInt64Attribute;
class StunByteStringAttribute;
class StunErrorCodeAttribute;
class StunUInt16ListAttribute;

// Records a complete STUN/TURN message.  Each message consists of a type and
// any number of attributes.  Each attribute is parsed into an instance of an
// appropriate class (see above).  The Get* methods will return instances of
// that attribute class.
class StunMessage : public rtcbase::MemCheck {
public:
    StunMessage();
    virtual ~StunMessage();

    int type() const { return _type; }
    size_t length() const { return _length; }
    const std::string& transaction_id() const { return _transaction_id; }
    
    // Returns true if the message confirms to RFC3489 rather than
    // RFC5389. The main difference between two version of the STUN
    // protocol is the presence of the magic cookie and different length
    // of transaction ID. For outgoing packets version of the protocol
    // is determined by the lengths of the transaction ID.
    bool is_legacy() const;
    
    void set_type(int type) { _type = static_cast<uint16_t>(type); }
    bool set_transaction_ID(const std::string& str);
    
    // Gets the desired attribute value, or NULL if no such attribute type exists.
    const StunAddressAttribute* get_address(int type) const;
    const StunUInt32Attribute* get_uint32(int type) const;
    const StunUInt64Attribute* get_uint64(int type) const;
    const StunByteStringAttribute* get_byte_string(int type) const;

    // Gets these specific attribute values.
    const StunErrorCodeAttribute* get_error_code() const;
    const StunUInt16ListAttribute* get_unknown_attributes() const;

    // Takes ownership of the specified attribute, verifies it is of the correct
    // type, and adds it to the message. The return value indicates whether this
    // was successful.
    void add_attribute(std::unique_ptr<StunAttribute> attr);
    
    // Validates that a raw STUN message has a correct MESSAGE-INTEGRITY value.
    // This can't currently be done on a StunMessage, since it is affected by
    // padding data (which we discard when reading a StunMessage).
    static bool validate_message_integrity(const char* data, size_t size,
            const std::string& password);
    // Adds a MESSAGE-INTEGRITY attribute that is valid for the current message.
    bool add_message_integrity(const std::string& password);
    bool add_message_integrity(const char* key, size_t keylen);
    
    // Verifies that a given buffer is STUN by checking for a correct FINGERPRINT.
    static bool validate_fingerprint(const char* data, size_t size);

    // Adds a FINGERPRINT attribute that is valid for the current message.
    bool add_fingerprint();

    // Parses the STUN packet in the given buffer and records it here. The
    // return value indicates whether this was successful.
    bool read(rtcbase::ByteBufferReader* buf);

    // Writes this object into a STUN packet. The return value indicates whether
    // this was successful.
    bool write(rtcbase::ByteBufferWriter* buf) const;

    // Creates an empty message. Overridable by derived classes.
    virtual StunMessage* create_new() const;

protected:
    // Verifies that the given attribute is allowed for this message.
    virtual StunAttributeValueType get_attribute_value_type(int type) const;

private:
    StunAttribute* create_attribute(int type, size_t length) /* const*/;
    const StunAttribute* get_attribute(int type) const;
    static bool is_valid_transaction_id(const std::string& transaction_id);

    uint16_t _type;
    uint16_t _length;
    std::string _transaction_id;
    std::vector<std::unique_ptr<StunAttribute>> _attrs;
    uint32_t _stun_magic_cookie;
};

// Base class for all STUN/TURN attributes.
class StunAttribute {
public:
    virtual ~StunAttribute() {}

    int type() const { return _type; }
    size_t length() const { return _length; }
    
    // Return the type of this attribute.
    virtual StunAttributeValueType value_type() const = 0;

    // Only XorAddressAttribute needs this so far.
    virtual void set_owner(StunMessage* owner) { (void)owner; }
    
    // Reads the body (not the type or length) for this type of attribute from
    // the given buffer.  Return value is true if successful.
    virtual bool read(rtcbase::ByteBufferReader* buf) = 0;

    // Writes the body (not the type or length) to the given buffer.  Return
    // value is true if successful.
    virtual bool write(rtcbase::ByteBufferWriter* buf) const = 0;
    
    // Creates an attribute object with the given type and smallest length.
    static StunAttribute* create(StunAttributeValueType value_type,
            uint16_t type,
            uint16_t length,
            StunMessage* owner);
    // TODO: Allow these create functions to take parameters, to reduce
    // the amount of work callers need to do to initialize attributes.
    static std::unique_ptr<StunAddressAttribute> create_address(uint16_t type);
    static std::unique_ptr<StunXorAddressAttribute> create_xor_address(uint16_t type);
    static std::unique_ptr<StunUInt32Attribute> create_uint32(uint16_t type);
    static std::unique_ptr<StunUInt64Attribute> create_uint64(uint16_t type);
    static std::unique_ptr<StunByteStringAttribute> create_byte_string(uint16_t type);
    static std::unique_ptr<StunErrorCodeAttribute> create_error_code();
    static std::unique_ptr<StunUInt16ListAttribute> create_unknown_attributes();

protected:
    StunAttribute(uint16_t type, uint16_t length);
    void set_length(uint16_t length) { _length = length; }
    void write_padding(rtcbase::ByteBufferWriter* buf) const;
    void consume_padding(rtcbase::ByteBufferReader* buf) const;

private:
    uint16_t _type;
    uint16_t _length;
};

// Implements STUN attributes that record an Internet address.
class StunAddressAttribute : public StunAttribute {
public:
    static const uint16_t SIZE_UNDEF = 0;
    static const uint16_t SIZE_IP4 = 8;
    static const uint16_t SIZE_IP6 = 20;
    StunAddressAttribute(uint16_t type, const rtcbase::SocketAddress& addr);
    StunAddressAttribute(uint16_t type, uint16_t length);

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_ADDRESS;
    }

    StunAddressFamily family() const {
        switch (_address.ipaddr().family()) {
            case AF_INET:
                return STUN_ADDRESS_IPV4;
            case AF_INET6:
                return STUN_ADDRESS_IPV6;
        }
        return STUN_ADDRESS_UNDEF;
    }

    const rtcbase::SocketAddress& get_address() const { return _address; }
    const rtcbase::IPAddress& ipaddr() const { return _address.ipaddr(); }
    uint16_t port() const { return _address.port(); }

    void set_address(const rtcbase::SocketAddress& addr) {
        _address = addr;
        ensure_address_length();
    }
    void set_IP(const rtcbase::IPAddress& ip) {
        _address.set_IP(ip);
        ensure_address_length();
    }
    void set_port(uint16_t port) { _address.set_port(port); }

    virtual bool read(rtcbase::ByteBufferReader* buf);
    virtual bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    void ensure_address_length() {
        switch (family()) {
            case STUN_ADDRESS_IPV4: {
                set_length(SIZE_IP4);
                break;
            }
            case STUN_ADDRESS_IPV6: {
                set_length(SIZE_IP6);
                break;
            }
            default: {
                set_length(SIZE_UNDEF);
                break;
            }
        }
    }
    rtcbase::SocketAddress _address;
};

// Implements STUN attributes that record an Internet address. When encoded
// in a STUN message, the address contained in this attribute is XORed with the
// transaction ID of the message.
class StunXorAddressAttribute : public StunAddressAttribute {
public:
    StunXorAddressAttribute(uint16_t type, const rtcbase::SocketAddress& addr);
    StunXorAddressAttribute(uint16_t type, uint16_t length, StunMessage* owner);

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_XOR_ADDRESS;
    }
    virtual void set_owner(StunMessage* owner) {
        _owner = owner;
    }
    virtual bool read(rtcbase::ByteBufferReader* buf);
    virtual bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    rtcbase::IPAddress get_xored_IP() const;
    StunMessage* _owner;
};

// Implements STUN attributes that record a 32-bit integer.
class StunUInt32Attribute : public StunAttribute {
public:
    static const uint16_t SIZE = 4;
    StunUInt32Attribute(uint16_t type, uint32_t value);
    explicit StunUInt32Attribute(uint16_t type);

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_UINT32;
    }

    uint32_t value() const { return _bits; }
    void set_value(uint32_t bits) { _bits = bits; }

    bool get_bit(size_t index) const;
    void set_bit(size_t index, bool value);

    virtual bool read(rtcbase::ByteBufferReader* buf);
    virtual bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    uint32_t _bits;
};

class StunUInt64Attribute : public StunAttribute {
public:
    static const uint16_t SIZE = 8;
    StunUInt64Attribute(uint16_t type, uint64_t value);
    explicit StunUInt64Attribute(uint16_t type);

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_UINT64;
    }

    uint64_t value() const { return _bits; }
    void set_value(uint64_t bits) { _bits = bits; }

    virtual bool read(rtcbase::ByteBufferReader* buf);
    virtual bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    uint64_t _bits;
};

// Implements STUN attributes that record an arbitrary byte string.
class StunByteStringAttribute : public StunAttribute {
public:
    explicit StunByteStringAttribute(uint16_t type);
    StunByteStringAttribute(uint16_t type, const std::string& str);
    StunByteStringAttribute(uint16_t type, const void* bytes, size_t length);
    StunByteStringAttribute(uint16_t type, uint16_t length);
    ~StunByteStringAttribute();
    
    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_BYTE_STRING;
    }

    const char* bytes() const { return _bytes; }
    std::string get_string() const { return std::string(_bytes, length()); }

    void copy_bytes(const char* bytes);  // uses strlen
    void copy_bytes(const void* bytes, size_t length);
    
    uint8_t get_byte(size_t index) const;
    void set_byte(size_t index, uint8_t value);

    virtual bool read(rtcbase::ByteBufferReader* buf);
    virtual bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    void set_bytes(char* bytes, size_t length);

    char* _bytes;
};

// Implements STUN attributes that record an error code.
class StunErrorCodeAttribute : public StunAttribute {
public:
    static const uint16_t MIN_SIZE;
    StunErrorCodeAttribute(uint16_t type, int code, const std::string& reason);
    StunErrorCodeAttribute(uint16_t type, uint16_t length);
    ~StunErrorCodeAttribute();

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_ERROR_CODE;
    }

    // The combined error and class, e.g. 0x400.
    int code() const;
    void set_code(int code);

    // The individual error components.
    int eclass() const { return _class; }
    int number() const { return _number; }
    const std::string& reason() const { return _reason; }
    void set_class(uint8_t eclass) { _class = eclass; }
    void set_number(uint8_t number) { _number = number; }
    void set_reason(const std::string& reason);

    bool read(rtcbase::ByteBufferReader* buf);
    bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    uint8_t _class;
    uint8_t _number;
    std::string _reason;
};

// Implements STUN attributes that record a list of attribute names.
class StunUInt16ListAttribute : public StunAttribute {
public:
    StunUInt16ListAttribute(uint16_t type, uint16_t length);
    ~StunUInt16ListAttribute();

    virtual StunAttributeValueType value_type() const {
        return STUN_VALUE_UINT16_LIST;
    }

    size_t size() const;
    uint16_t get_type(int index) const;
    void set_type(int index, uint16_t value);
    void add_type(uint16_t value);

    bool read(rtcbase::ByteBufferReader* buf);
    bool write(rtcbase::ByteBufferWriter* buf) const;

private:
    std::vector<uint16_t>* _attr_types;
};

// Returns the (successful) response type for the given request type.
// Returns -1 if |request_type| is not a valid request type.
int get_stun_success_response_type(int request_type);

// Returns the error response type for the given request type.
// Returns -1 if |request_type| is not a valid request type.
int get_stun_error_response_type(int request_type);

// Returns whether a given message is a request type.
bool is_stun_request_type(int msg_type);

// Returns whether a given message is an indication type.
bool is_stun_indication_type(int msg_type);

// Returns whether a given response is a success type.
bool is_stun_success_response_type(int msg_type);

// Returns whether a given response is an error type.
bool is_stun_error_response_type(int msg_type);

// RFC 5245 ICE STUN attributes.
enum IceAttributeType {
    STUN_ATTR_PRIORITY = 0x0024,         // UInt32
    STUN_ATTR_USE_CANDIDATE = 0x0025,    // No content, Length = 0
    STUN_ATTR_ICE_CONTROLLED = 0x8029,   // UInt64
    STUN_ATTR_ICE_CONTROLLING = 0x802A,  // UInt64
    STUN_ATTR_NOMINATION = 0xC001,       // UInt32
    // UInt32. The higher 16 bits are the network ID. The lower 16 bits are the
    // network cost.
    STUN_ATTR_NETWORK_INFO = 0xC057
};

// RFC 5245-defined errors.
enum IceErrorCode {
    STUN_ERROR_ROLE_CONFLICT              = 487,
};
extern const char STUN_ERROR_REASON_ROLE_CONFLICT[];

// A RFC 5245 ICE STUN message.
class IceMessage : public StunMessage {
protected:
    StunAttributeValueType get_attribute_value_type(int type) const override;
    StunMessage* create_new() const override;
};

} // namespace ice

#endif  //__ICE_STUN_H_


