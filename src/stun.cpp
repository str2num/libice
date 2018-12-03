/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun.cpp
 * @author str2num
 * @brief 
 *  
 **/


#include <string.h>

#include <memory>

#include <rtcbase/ptr_utils.h>
#include <rtcbase/byte_order.h>
#include <rtcbase/crc32.h>
#include <rtcbase/logging.h>
#include <rtcbase/message_digest.h>
#include <rtcbase/string_encode.h>
#include "stun.h"

namespace ice {

const char STUN_ERROR_REASON_TRY_ALTERNATE_SERVER[] = "Try Alternate Server";
const char STUN_ERROR_REASON_BAD_REQUEST[] = "Bad Request";
const char STUN_ERROR_REASON_UNAUTHORIZED[] = "Unauthorized";
const char STUN_ERROR_REASON_FORBIDDEN[] = "Forbidden";
const char STUN_ERROR_REASON_STALE_CREDENTIALS[] = "Stale Credentials";
const char STUN_ERROR_REASON_ALLOCATION_MISMATCH[] = "Allocation Mismatch";
const char STUN_ERROR_REASON_STALE_NONCE[] = "Stale Nonce";
const char STUN_ERROR_REASON_WRONG_CREDENTIALS[] = "Wrong Credentials";
const char STUN_ERROR_REASON_UNSUPPORTED_PROTOCOL[] = "Unsupported Protocol";
const char STUN_ERROR_REASON_ROLE_CONFLICT[] = "Role Conflict";
const char STUN_ERROR_REASON_SERVER_ERROR[] = "Server Error";

const char TURN_MAGIC_COOKIE_VALUE[] = { '\x72', '\xC6', '\x4B', '\xC6' };
const char EMPTY_TRANSACTION_ID[] = "0000000000000000";
const uint32_t STUN_FINGERPRINT_XOR_VALUE = 0x5354554E;

////////////////// StunMessage //////////////////////

StunMessage::StunMessage()
    : rtcbase::MemCheck("StunMessage"),
    _type(0),
    _length(0),
    _transaction_id(EMPTY_TRANSACTION_ID),
    _stun_magic_cookie(k_stun_magic_cookie)
{
}

StunMessage::~StunMessage() = default;

bool StunMessage::is_legacy() const {
    if (_transaction_id.size() == k_stun_legacy_transaction_id_length) {
        return true;
    }
    return false;
}

const StunAddressAttribute* StunMessage::get_address(int type) const {
    switch (type) {
        case STUN_ATTR_MAPPED_ADDRESS: {
            // Return XOR-MAPPED-ADDRESS when MAPPED-ADDRESS attribute is
            // missing.
            const StunAttribute* mapped_address =
                get_attribute(STUN_ATTR_MAPPED_ADDRESS);
            if (!mapped_address) {
                mapped_address = get_attribute(STUN_ATTR_XOR_MAPPED_ADDRESS);
            }
            return reinterpret_cast<const StunAddressAttribute*>(mapped_address);
        }

        default:
            return static_cast<const StunAddressAttribute*>(get_attribute(type));
    }
}

const StunUInt32Attribute* StunMessage::get_uint32(int type) const {
    return static_cast<const StunUInt32Attribute*>(get_attribute(type));
}

const StunUInt64Attribute* StunMessage::get_uint64(int type) const {
    return static_cast<const StunUInt64Attribute*>(get_attribute(type));
}

const StunByteStringAttribute* StunMessage::get_byte_string(int type) const {
    return static_cast<const StunByteStringAttribute*>(get_attribute(type));
}

const StunErrorCodeAttribute* StunMessage::get_error_code() const {
    return static_cast<const StunErrorCodeAttribute*>(
            get_attribute(STUN_ATTR_ERROR_CODE));
}

const StunUInt16ListAttribute* StunMessage::get_unknown_attributes() const {
    return static_cast<const StunUInt16ListAttribute*>(
            get_attribute(STUN_ATTR_UNKNOWN_ATTRIBUTES));
}

// Verifies a STUN message has a valid MESSAGE-INTEGRITY attribute, using the
// procedure outlined in RFC 5389, section 15.4.
bool StunMessage::validate_message_integrity(const char* data, size_t size,
        const std::string& password) 
{
    // Verifying the size of the message.
    if ((size % 4) != 0 || size < k_stun_header_size) {
        return false;
    }

    // Getting the message length from the STUN header.
    uint16_t msg_length = rtcbase::get_be16(&data[2]);
    if (size != (msg_length + k_stun_header_size)) {
        return false;
    }

    // Finding Message Integrity attribute in stun message.
    size_t current_pos = k_stun_header_size;
    bool has_message_integrity_attr = false;
    while (current_pos + 4 <= size) {
        uint16_t attr_type, attr_length;
        // Getting attribute type and length.
        attr_type = rtcbase::get_be16(&data[current_pos]);
        attr_length = rtcbase::get_be16(&data[current_pos + sizeof(attr_type)]);

        // If M-I, sanity check it, and break out.
        if (attr_type == STUN_ATTR_MESSAGE_INTEGRITY) {
            if (attr_length != k_stun_message_integrity_size ||
                    current_pos + sizeof(attr_type) + sizeof(attr_length) + attr_length >
                    size) {
                return false;
            }
            has_message_integrity_attr = true;
            break;
        }

        // Otherwise, skip to the next attribute.
        current_pos += sizeof(attr_type) + sizeof(attr_length) + attr_length;
        if ((attr_length % 4) != 0) {
            current_pos += (4 - (attr_length % 4));
        }
    }

    if (!has_message_integrity_attr) {
        return false;
    }

    // Getting length of the message to calculate Message Integrity.
    size_t mi_pos = current_pos;
    std::unique_ptr<char[]> temp_data(new char[current_pos]);
    memcpy(temp_data.get(), data, current_pos);
    if (size > mi_pos + k_stun_attribute_header_size + k_stun_message_integrity_size) {
        // Stun message has other attributes after message integrity.
        // Adjust the length parameter in stun message to calculate HMAC.
        size_t extra_offset = size -
            (mi_pos + k_stun_attribute_header_size + k_stun_message_integrity_size);
        size_t new_adjusted_len = size - extra_offset - k_stun_header_size;

        // Writing new length of the STUN message @ Message Length in temp buffer.
        //      0                   1                   2                   3
        //      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //     |0 0|     STUN Message Type     |         Message Length        |
        //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        rtcbase::set_be16(temp_data.get() + 2, static_cast<uint16_t>(new_adjusted_len));
    }

    char hmac[k_stun_message_integrity_size];
    size_t ret = rtcbase::compute_hmac(rtcbase::DIGEST_SHA_1,
            password.c_str(), password.size(),
            temp_data.get(), mi_pos,
            hmac, sizeof(hmac));
    if (ret != sizeof(hmac)) {
        return false;
    }

    // Comparing the calculated HMAC with the one present in the message.
    return memcmp(data + current_pos + k_stun_attribute_header_size,
            hmac,
            sizeof(hmac)) == 0;
}

bool StunMessage::set_transaction_ID(const std::string& str) {
    if (!is_valid_transaction_id(str)) {
        return false;
    }
    _transaction_id = str;
    return true;
}

static bool designated_expert_range(int attr_type) {
    return (attr_type >= 0x4000 && attr_type <= 0x7FFF) ||
        (attr_type >= 0xC000 && attr_type <= 0xFFFF);
}

void StunMessage::add_attribute(std::unique_ptr<StunAttribute> attr) {
    // Fail any attributes that aren't valid for this type of message.
    // but allow any type for the range that in the RFC is reserved for
    // the "designated experts".
    if (!designated_expert_range(attr->type())) {
        if (attr->value_type() != get_attribute_value_type(attr->type())) {
            return;
        }
    }
    attr->set_owner(this);
    size_t attr_length = attr->length();
    if (attr_length % 4 != 0) {
        attr_length += (4 - (attr_length % 4));
    }
    _length += static_cast<uint16_t>(attr_length + 4);
    _attrs.push_back(std::move(attr));
}

bool StunMessage::add_message_integrity(const std::string& password) {
    return add_message_integrity(password.c_str(), password.size());
}

bool StunMessage::add_message_integrity(const char* key, size_t keylen) {
    // Add the attribute with a dummy value. Since this is a known attribute, it
    // can't fail.
    auto msg_integrity_attr_ptr = rtcbase::make_unique<StunByteStringAttribute>(
            STUN_ATTR_MESSAGE_INTEGRITY, std::string(k_stun_message_integrity_size, '0'));
    auto* msg_integrity_attr = msg_integrity_attr_ptr.get();
    add_attribute(std::move(msg_integrity_attr_ptr));
 
    // Calculate the HMAC for the message.
    rtcbase::ByteBufferWriter buf;
    if (!write(&buf)) {
        return false;
    }

    int msg_len_for_hmac = static_cast<int>(
            buf.length() - k_stun_attribute_header_size - msg_integrity_attr->length());
    char hmac[k_stun_message_integrity_size];
    size_t ret = rtcbase::compute_hmac(rtcbase::DIGEST_SHA_1,
            key, keylen,
            buf.data(), msg_len_for_hmac,
            hmac, sizeof(hmac));
    if (ret != sizeof(hmac)) {
        LOG(LS_WARNING) << "HMAC computation failed. Message-Integrity "
            << "has dummy value.";
        return false;
    }

    // Insert correct HMAC into the attribute.
    msg_integrity_attr->copy_bytes(hmac, sizeof(hmac));
    return true;
}

// Verifies a message is in fact a STUN message, by performing the checks
// outlined in RFC 5389, section 7.3, including the FINGERPRINT check detailed
// in section 15.5.
bool StunMessage::validate_fingerprint(const char* data, size_t size) {
    // Check the message length.
    size_t fingerprint_attr_size =
        k_stun_attribute_header_size + StunUInt32Attribute::SIZE;
    if (size % 4 != 0 || size < k_stun_header_size + fingerprint_attr_size) {
        return false;
    }

    // Skip the rest if the magic cookie isn't present.
    const char* magic_cookie =
        data + k_stun_transaction_id_offset - k_stun_magic_cookie_length;
    if (rtcbase::get_be32(magic_cookie) != k_stun_magic_cookie) {
        return false;
    }

    // Check the fingerprint type and length.
    const char* fingerprint_attr_data = data + size - fingerprint_attr_size;
    if (rtcbase::get_be16(fingerprint_attr_data) != STUN_ATTR_FINGERPRINT ||
            rtcbase::get_be16(fingerprint_attr_data + sizeof(uint16_t)) !=
            StunUInt32Attribute::SIZE)
    {
        return false;
    }

    // Check the fingerprint value.
    uint32_t fingerprint =
        rtcbase::get_be32(fingerprint_attr_data + k_stun_attribute_header_size);
    return ((fingerprint ^ STUN_FINGERPRINT_XOR_VALUE) ==
            rtcbase::compute_crc32(data, size - fingerprint_attr_size));
}

bool StunMessage::add_fingerprint() {
    // Add the attribute with a dummy value. Since this is a known attribute,
    // it can't fail.
    auto fingerprint_attr_ptr =
        rtcbase::make_unique<StunUInt32Attribute>(STUN_ATTR_FINGERPRINT, 0);
    auto* fingerprint_attr = fingerprint_attr_ptr.get();
    add_attribute(std::move(fingerprint_attr_ptr));
 
    // Calculate the CRC-32 for the message and insert it.
    rtcbase::ByteBufferWriter buf;
    if (!write(&buf)) {
        return false;
    }

    int msg_len_for_crc32 = static_cast<int>(
            buf.length() - k_stun_attribute_header_size - fingerprint_attr->length());
    uint32_t c = rtcbase::compute_crc32(buf.data(), msg_len_for_crc32);

    // Insert the correct CRC-32, XORed with a constant, into the attribute.
    fingerprint_attr->set_value(c ^ STUN_FINGERPRINT_XOR_VALUE);
    return true;
}

bool StunMessage::read(rtcbase::ByteBufferReader* buf) {
    if (!buf->read_uint16(&_type)) {
        return false;
    }

    if (_type & 0x8000) {
        // RTP and RTCP set the MSB of first byte, since first two bits are version,
        // and version is always 2 (10). If set, this is not a STUN packet.
        return false;
    }

    if (!buf->read_uint16(&_length)) {
        return false;
    }

    std::string magic_cookie;
    if (!buf->read_string(&magic_cookie, k_stun_magic_cookie_length)) {
        return false;
    }

    std::string transaction_id;
    if (!buf->read_string(&transaction_id, k_stun_transaction_id_length)) {
        return false;
    }

    uint32_t magic_cookie_int =
        *reinterpret_cast<const uint32_t*>(magic_cookie.data());
    if (rtcbase::network_to_host32(magic_cookie_int) != k_stun_magic_cookie) {
        // If magic cookie is invalid it means that the peer implements
        // RFC3489 instead of RFC5389.
        transaction_id.insert(0, magic_cookie);
    }
    if (!is_valid_transaction_id(transaction_id)) {
        return false;
    }
    _transaction_id = transaction_id;

    if (_length != buf->length()) {
        return false;
    }

    _attrs.resize(0);

    size_t rest = buf->length() - _length;
    while (buf->length() > rest) {
        uint16_t attr_type, attr_length;
        if (!buf->read_uint16(&attr_type)) {
            return false;
        }
        if (!buf->read_uint16(&attr_length)) {
            return false;
        }

        std::unique_ptr<StunAttribute> attr(create_attribute(attr_type, attr_length));
        if (!attr) {
            // Skip any unknown or malformed attributes.
            if ((attr_length % 4) != 0) {
                attr_length += (4 - (attr_length % 4));
            }
            if (!buf->consume(attr_length)) {
                return false;
            }
        } else {
            if (!attr->read(buf)) {
                return false;
            }
            _attrs.push_back(std::move(attr));
        }
    }

    if (buf->length() != rest) {
        return false;
    }
    return true;
}

bool StunMessage::write(rtcbase::ByteBufferWriter* buf) const {
    buf->write_uint16(_type);
    buf->write_uint16(_length);
    if (!is_legacy()) {
        buf->write_uint32(k_stun_magic_cookie);
    }
    buf->write_string(_transaction_id);
    
    for (const auto& attr : _attrs) {
        buf->write_uint16(attr->type());
        buf->write_uint16(static_cast<uint16_t>(attr->length()));
        if (!attr->write(buf)) {
            return false;
        }
    }

    return true;
}

StunMessage* StunMessage::create_new() const {
    return new StunMessage();
}

StunAttributeValueType StunMessage::get_attribute_value_type(int type) const {
    switch (type) {
        case STUN_ATTR_MAPPED_ADDRESS:      return STUN_VALUE_ADDRESS;
        case STUN_ATTR_USERNAME:            return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_MESSAGE_INTEGRITY:   return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_ERROR_CODE:          return STUN_VALUE_ERROR_CODE;
        case STUN_ATTR_UNKNOWN_ATTRIBUTES:  return STUN_VALUE_UINT16_LIST;
        case STUN_ATTR_REALM:               return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_NONCE:               return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_XOR_MAPPED_ADDRESS:  return STUN_VALUE_XOR_ADDRESS;
        case STUN_ATTR_SOFTWARE:            return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_ALTERNATE_SERVER:    return STUN_VALUE_ADDRESS;
        case STUN_ATTR_FINGERPRINT:         return STUN_VALUE_UINT32;
        case STUN_ATTR_ORIGIN:              return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_RETRANSMIT_COUNT:    return STUN_VALUE_UINT32;
        default:                            return STUN_VALUE_UNKNOWN;
    }
}

StunAttribute* StunMessage::create_attribute(int type, size_t length) /*const*/ {
    StunAttributeValueType value_type = get_attribute_value_type(type);
    if (value_type != STUN_VALUE_UNKNOWN) {
        return StunAttribute::create(value_type, type,
                static_cast<uint16_t>(length), this);
    } else if (designated_expert_range(type)) {
        // Read unknown attributes as STUN_VALUE_BYTE_STRING
        return StunAttribute::create(STUN_VALUE_BYTE_STRING, type,
                static_cast<uint16_t>(length), this);
    } else {
        return NULL;
    }
}

const StunAttribute* StunMessage::get_attribute(int type) const {
    for (const auto& attr : _attrs) {
        if (attr->type() == type) {
            return attr.get();
        }
    }
    return NULL;
}

bool StunMessage::is_valid_transaction_id(const std::string& transaction_id) {
    return transaction_id.size() == k_stun_transaction_id_length ||
        transaction_id.size() == k_stun_legacy_transaction_id_length;
}

////////////////// StunAttribute //////////////////////

StunAttribute::StunAttribute(uint16_t type, uint16_t length) : 
    _type(type), _length(length) 
{
}

StunAttribute* StunAttribute::create(StunAttributeValueType value_type,
        uint16_t type,
        uint16_t length,
        StunMessage* owner) 
{
    switch (value_type) {
        case STUN_VALUE_ADDRESS:
            return new StunAddressAttribute(type, length);
        case STUN_VALUE_XOR_ADDRESS:
            return new StunXorAddressAttribute(type, length, owner);
        case STUN_VALUE_UINT32:
            return new StunUInt32Attribute(type);
        case STUN_VALUE_UINT64:
            return new StunUInt64Attribute(type);
        case STUN_VALUE_BYTE_STRING:
            return new StunByteStringAttribute(type, length);
        case STUN_VALUE_ERROR_CODE:
            return new StunErrorCodeAttribute(type, length);
        case STUN_VALUE_UINT16_LIST:
            return new StunUInt16ListAttribute(type, length);
        default:
            return NULL;
    }
}

std::unique_ptr<StunAddressAttribute> StunAttribute::create_address(uint16_t type) {
    return rtcbase::make_unique<StunAddressAttribute>(type, 0);
}

std::unique_ptr<StunXorAddressAttribute> StunAttribute::create_xor_address(uint16_t type) {
    return rtcbase::make_unique<StunXorAddressAttribute>(type, 0, nullptr);
}

std::unique_ptr<StunUInt64Attribute> StunAttribute::create_uint64(uint16_t type) {
    return rtcbase::make_unique<StunUInt64Attribute>(type);
}

std::unique_ptr<StunUInt32Attribute> StunAttribute::create_uint32(uint16_t type) {
    return rtcbase::make_unique<StunUInt32Attribute>(type);
}

std::unique_ptr<StunByteStringAttribute> StunAttribute::create_byte_string(uint16_t type) {
    return rtcbase::make_unique<StunByteStringAttribute>(type, 0);
}

std::unique_ptr<StunErrorCodeAttribute> StunAttribute::create_error_code() {
    return rtcbase::make_unique<StunErrorCodeAttribute>(
            STUN_ATTR_ERROR_CODE, StunErrorCodeAttribute::MIN_SIZE);
}

std::unique_ptr<StunUInt16ListAttribute> StunAttribute::create_unknown_attributes() {
    return rtcbase::make_unique<StunUInt16ListAttribute>(STUN_ATTR_UNKNOWN_ATTRIBUTES, 0);
}

void StunAttribute::consume_padding(rtcbase::ByteBufferReader* buf) const {
    int remainder = _length % 4;
    if (remainder > 0) {
        buf->consume(4 - remainder);
    }
}

void StunAttribute::write_padding(rtcbase::ByteBufferWriter* buf) const {
    int remainder = _length % 4;
    if (remainder > 0) {
        char zeroes[4] = {0};
        buf->write_bytes(zeroes, 4 - remainder);
    }
}

/////////////////// StunAddressAttribute //////////////////////

StunAddressAttribute::StunAddressAttribute(uint16_t type,
        const rtcbase::SocketAddress& addr)
    : StunAttribute(type, 0) 
{
    set_address(addr);
}

StunAddressAttribute::StunAddressAttribute(uint16_t type, uint16_t length)
    : StunAttribute(type, length) 
{
}

bool StunAddressAttribute::read(rtcbase::ByteBufferReader* buf) {
    uint8_t dummy;
    if (!buf->read_uint8(&dummy)) {
        return false;
    }

    uint8_t stun_family;
    if (!buf->read_uint8(&stun_family)) {
        return false;
    }
    uint16_t port;
    if (!buf->read_uint16(&port)) {
        return false;
    }
    if (stun_family == STUN_ADDRESS_IPV4) {
        in_addr v4addr;
        if (length() != SIZE_IP4) {
            return false;
        }
        if (!buf->read_bytes(reinterpret_cast<char*>(&v4addr), sizeof(v4addr))) {
            return false;
        }
        rtcbase::IPAddress ipaddr(v4addr);
        set_address(rtcbase::SocketAddress(ipaddr, port));
    } else if (stun_family == STUN_ADDRESS_IPV6) {
        in6_addr v6addr;
        if (length() != SIZE_IP6) {
            return false;
        }
        if (!buf->read_bytes(reinterpret_cast<char*>(&v6addr), sizeof(v6addr))) {
            return false;
        }
        rtcbase::IPAddress ipaddr(v6addr);
        set_address(rtcbase::SocketAddress(ipaddr, port));
    } else {
        return false;
    }
    return true;
}

bool StunAddressAttribute::write(rtcbase::ByteBufferWriter* buf) const {
    StunAddressFamily address_family = family();
    if (address_family == STUN_ADDRESS_UNDEF) {
        LOG(LS_WARNING) << "Error writing address attribute: unknown family.";
        return false;
    }
    buf->write_uint8(0);
    buf->write_uint8(address_family);
    buf->write_uint16(_address.port());
    switch (_address.family()) {
        case AF_INET: {
            in_addr v4addr = _address.ipaddr().ipv4_address();
            buf->write_bytes(reinterpret_cast<char*>(&v4addr), sizeof(v4addr));
            break;
        }
        case AF_INET6: {
            in6_addr v6addr = _address.ipaddr().ipv6_address();
            buf->write_bytes(reinterpret_cast<char*>(&v6addr), sizeof(v6addr));
            break;
        }
    }
    return true;
}

///////////////////// StunXorAddressAttribute ///////////////////////////

StunXorAddressAttribute::StunXorAddressAttribute(uint16_t type,
        const rtcbase::SocketAddress& addr)
    : StunAddressAttribute(type, addr), _owner(NULL) 
{
}

StunXorAddressAttribute::StunXorAddressAttribute(uint16_t type,
        uint16_t length,
        StunMessage* owner)
    : StunAddressAttribute(type, length), _owner(owner) 
{
}

rtcbase::IPAddress StunXorAddressAttribute::get_xored_IP() const {
    if (_owner) {
        rtcbase::IPAddress ip = ipaddr();
        switch (ip.family()) {
            case AF_INET: {
                in_addr v4addr = ip.ipv4_address();
                v4addr.s_addr = (v4addr.s_addr ^ rtcbase::host_to_network32(k_stun_magic_cookie));
                return rtcbase::IPAddress(v4addr);
            }
            case AF_INET6: {
                in6_addr v6addr = ip.ipv6_address();
                const std::string& transaction_id = _owner->transaction_id();
                if (transaction_id.length() == k_stun_transaction_id_length) {
                    uint32_t transactionid_as_ints[3];
                    memcpy(&transactionid_as_ints[0], transaction_id.c_str(),
                            transaction_id.length());
                    uint32_t* ip_as_ints = reinterpret_cast<uint32_t*>(&v6addr.s6_addr);
                    // Transaction ID is in network byte order, but magic cookie
                    // is stored in host byte order.
                    ip_as_ints[0] =
                        (ip_as_ints[0] ^ rtcbase::host_to_network32(k_stun_magic_cookie));
                    ip_as_ints[1] = (ip_as_ints[1] ^ transactionid_as_ints[0]);
                    ip_as_ints[2] = (ip_as_ints[2] ^ transactionid_as_ints[1]);
                    ip_as_ints[3] = (ip_as_ints[3] ^ transactionid_as_ints[2]);
                    return rtcbase::IPAddress(v6addr);
                }
                break;
            }
        }
    }
    // Invalid ip family or transaction ID, or missing owner.
    // Return an AF_UNSPEC address.
    return rtcbase::IPAddress();
}

bool StunXorAddressAttribute::read(rtcbase::ByteBufferReader* buf) {
    if (!StunAddressAttribute::read(buf)) {
        return false;
    }
    uint16_t xoredport = port() ^ (k_stun_magic_cookie >> 16);
    rtcbase::IPAddress xored_ip = get_xored_IP();
    set_address(rtcbase::SocketAddress(xored_ip, xoredport));
    return true;
}

bool StunXorAddressAttribute::write(rtcbase::ByteBufferWriter* buf) const {
    StunAddressFamily address_family = family();
    if (address_family == STUN_ADDRESS_UNDEF) {
        LOG(LS_WARNING) << "Error writing xor-address attribute: unknown family.";
        return false;
    }
    rtcbase::IPAddress xored_ip = get_xored_IP();
    if (xored_ip.family() == AF_UNSPEC) {
        return false;
    }
    buf->write_uint8(0);
    buf->write_uint8(family());
    buf->write_uint16(port() ^ (k_stun_magic_cookie >> 16));
    switch (xored_ip.family()) {
        case AF_INET: {
            in_addr v4addr = xored_ip.ipv4_address();
            buf->write_bytes(reinterpret_cast<const char*>(&v4addr), sizeof(v4addr));
            break;
        }
        case AF_INET6: {
            in6_addr v6addr = xored_ip.ipv6_address();
            buf->write_bytes(reinterpret_cast<const char*>(&v6addr), sizeof(v6addr));
            break;
        }
    }
    return true;
}

///////////////// StunUInt32Attribute ///////////////////

StunUInt32Attribute::StunUInt32Attribute(uint16_t type, uint32_t value)
    : StunAttribute(type, SIZE), _bits(value) 
{
}

StunUInt32Attribute::StunUInt32Attribute(uint16_t type)
    : StunAttribute(type, SIZE), _bits(0) 
{
}

bool StunUInt32Attribute::get_bit(size_t index) const {
  if (index >= 32) {
      return false;
  }
  return static_cast<bool>((_bits >> index) & 0x1);
}

void StunUInt32Attribute::set_bit(size_t index, bool value) {
    if (index < 32) {
        return;
    }
    _bits &= ~(1 << index);
    _bits |= value ? (1 << index) : 0;
}

bool StunUInt32Attribute::read(rtcbase::ByteBufferReader* buf) {
    if (length() != SIZE || !buf->read_uint32(&_bits)) {
        return false;
    }
    return true;
}

bool StunUInt32Attribute::write(rtcbase::ByteBufferWriter* buf) const {
    buf->write_uint32(_bits);
    return true;
}

/////////////////////// StunUInt64Attribute /////////////////////

StunUInt64Attribute::StunUInt64Attribute(uint16_t type, uint64_t value)
    : StunAttribute(type, SIZE), _bits(value) {
}

StunUInt64Attribute::StunUInt64Attribute(uint16_t type)
    : StunAttribute(type, SIZE), _bits(0) {
}

bool StunUInt64Attribute::read(rtcbase::ByteBufferReader* buf) {
    if (length() != SIZE || !buf->read_uint64(&_bits)) {
        return false;
    }
    return true;
}

bool StunUInt64Attribute::write(rtcbase::ByteBufferWriter* buf) const {
    buf->write_uint64(_bits);
    return true;
}

////////////////// StunByteStringAttribute ////////////////////

StunByteStringAttribute::StunByteStringAttribute(uint16_t type) : 
    StunAttribute(type, 0), _bytes(NULL) 
{
}

StunByteStringAttribute::StunByteStringAttribute(uint16_t type,
        const std::string& str) : 
    StunAttribute(type, 0), _bytes(NULL) 
{
    copy_bytes(str.c_str(), str.size());
}

StunByteStringAttribute::StunByteStringAttribute(uint16_t type,
        const void* bytes,
        size_t length) : 
    StunAttribute(type, 0), _bytes(NULL) 
{
    copy_bytes(bytes, length);
}

StunByteStringAttribute::StunByteStringAttribute(uint16_t type, uint16_t length) : 
    StunAttribute(type, length), _bytes(NULL) 
{
}

StunByteStringAttribute::~StunByteStringAttribute() {
    delete [] _bytes;
}

void StunByteStringAttribute::copy_bytes(const char* bytes) {
    copy_bytes(bytes, strlen(bytes));
}

void StunByteStringAttribute::copy_bytes(const void* bytes, size_t length) {
    char* new_bytes = new char[length];
    memcpy(new_bytes, bytes, length);
    set_bytes(new_bytes, length);
}

void StunByteStringAttribute::set_bytes(char* bytes, size_t length) {
    delete [] _bytes;
    _bytes = bytes;
    set_length(static_cast<uint16_t>(length));
}

uint8_t StunByteStringAttribute::get_byte(size_t index) const {
    if (_bytes == NULL || index >= length()) {
        return 0;
    }
    return static_cast<uint8_t>(_bytes[index]);
}

void StunByteStringAttribute::set_byte(size_t index, uint8_t value) {
    if (_bytes == NULL || index >= length()) {
        return;
    } 
    _bytes[index] = value;
}

bool StunByteStringAttribute::read(rtcbase::ByteBufferReader* buf) {
    _bytes = new char[length()];
    if (!buf->read_bytes(_bytes, length())) {
        return false;
    }

    consume_padding(buf);
    return true;
}

bool StunByteStringAttribute::write(rtcbase::ByteBufferWriter* buf) const {
    buf->write_bytes(_bytes, length());
    write_padding(buf);
    return true;
}

///////////////////// StunErrorCodeAttribute ///////////////////////

const uint16_t StunErrorCodeAttribute::MIN_SIZE = 4;

StunErrorCodeAttribute::StunErrorCodeAttribute(uint16_t type,
        int code,
        const std::string& reason)
    : StunAttribute(type, 0) 
{
    set_code(code);
    set_reason(reason);
}

StunErrorCodeAttribute::StunErrorCodeAttribute(uint16_t type, uint16_t length)
    : StunAttribute(type, length), _class(0), _number(0) 
{
}

StunErrorCodeAttribute::~StunErrorCodeAttribute() {
}

int StunErrorCodeAttribute::code() const {
    return _class * 100 + _number;
}

void StunErrorCodeAttribute::set_code(int code) {
    _class = static_cast<uint8_t>(code / 100);
    _number = static_cast<uint8_t>(code % 100);
}

void StunErrorCodeAttribute::set_reason(const std::string& reason) {
    set_length(MIN_SIZE + static_cast<uint16_t>(reason.size()));
    _reason = reason;
}

bool StunErrorCodeAttribute::read(rtcbase::ByteBufferReader* buf) {
    uint32_t val;
    if (length() < MIN_SIZE || !buf->read_uint32(&val)) {
        return false;
    }

    if ((val >> 11) != 0) {
        LOG(LS_WARNING) << "error-code bits not zero";
    }

    _class = ((val >> 8) & 0x7);
    _number = (val & 0xff);

    if (!buf->read_string(&_reason, length() - 4)) {
        return false;
    }

    consume_padding(buf);
    return true;
}

bool StunErrorCodeAttribute::write(rtcbase::ByteBufferWriter* buf) const {
    buf->write_uint32(_class << 8 | _number);
    buf->write_string(_reason);
    write_padding(buf);
    return true;
}

///////////////////// StunUInt16ListAttribute /////////////////////////

StunUInt16ListAttribute::StunUInt16ListAttribute(uint16_t type, uint16_t length)
    : StunAttribute(type, length) 
{
    _attr_types = new std::vector<uint16_t>();
}

StunUInt16ListAttribute::~StunUInt16ListAttribute() {
    delete _attr_types;
}

size_t StunUInt16ListAttribute::size() const {
    return _attr_types->size();
}

uint16_t StunUInt16ListAttribute::get_type(int index) const {
    return (*_attr_types)[index];
}

void StunUInt16ListAttribute::set_type(int index, uint16_t value) {
    (*_attr_types)[index] = value;
}

void StunUInt16ListAttribute::add_type(uint16_t value) {
    _attr_types->push_back(value);
    set_length(static_cast<uint16_t>(_attr_types->size() * 2));
}

bool StunUInt16ListAttribute::read(rtcbase::ByteBufferReader* buf) {
    if (length() % 2)
        return false;

    for (size_t i = 0; i < length() / 2; i++) {
        uint16_t attr;
        if (!buf->read_uint16(&attr)) {
            return false;
        }
        _attr_types->push_back(attr);
    }
    // Padding of these attributes is done in RFC 5389 style. This is
    // slightly different from RFC3489, but it shouldn't be important.
    // RFC3489 pads out to a 32 bit boundary by duplicating one of the
    // entries in the list (not necessarily the last one - it's unspecified).
    // RFC5389 pads on the end, and the bytes are always ignored.
    consume_padding(buf);
    return true;
}

bool StunUInt16ListAttribute::write(rtcbase::ByteBufferWriter* buf) const {
    for (size_t i = 0; i < _attr_types->size(); ++i) {
        buf->write_uint16((*_attr_types)[i]);
    }
    write_padding(buf);
    return true;
}

int get_stun_success_response_type(int req_type) {
    return is_stun_request_type(req_type) ? (req_type | 0x100) : -1;
}

int get_stun_error_response_type(int req_type) {
    return is_stun_request_type(req_type) ? (req_type | 0x110) : -1;
}

bool is_stun_request_type(int msg_type) {
    return ((msg_type & k_stun_type_mask) == 0x000);
}

bool is_stun_indication_type(int msg_type) {
    return ((msg_type & k_stun_type_mask) == 0x010);
}

bool is_stun_success_response_type(int msg_type) {
    return ((msg_type & k_stun_type_mask) == 0x100);
}

bool is_stun_error_response_type(int msg_type) {
    return ((msg_type & k_stun_type_mask) == 0x110);
}

StunAttributeValueType IceMessage::get_attribute_value_type(int type) const {
    switch (type) {
        case STUN_ATTR_PRIORITY:
        case STUN_ATTR_NETWORK_INFO:
        case STUN_ATTR_NOMINATION:
            return STUN_VALUE_UINT32;
        case STUN_ATTR_USE_CANDIDATE:   return STUN_VALUE_BYTE_STRING;
        case STUN_ATTR_ICE_CONTROLLED:  return STUN_VALUE_UINT64;
        case STUN_ATTR_ICE_CONTROLLING: return STUN_VALUE_UINT64;
        default: return StunMessage::get_attribute_value_type(type);
    }
}

StunMessage* IceMessage::create_new() const {
    return new IceMessage();
}

} // namespace ice


