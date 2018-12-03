/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun_request.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <algorithm>
#include <memory>

#include <rtcbase/ptr_utils.h>
#include <rtcbase/random.h>
#include <rtcbase/logging.h>
#include <rtcbase/string_encode.h>
#include <rtcbase/time_utils.h>
#include "stun_request.h"

namespace ice {

const uint32_t MSG_STUN_SEND = 1;

// RFC 5389 says SHOULD be 500ms.
// For years, this was 100ms, but for networks that
// experience moments of high RTT (such as 2G networks), this doesn't
// work well.
const int STUN_INITIAL_RTO = 250;  // milliseconds

// The timeout doubles each retransmission, up to this many times
// RFC 5389 says SHOULD retransmit 7 times.
// This has been 8 for years (not sure why).
const int STUN_MAX_RETRANSMISSIONS = 8;  // Total sends: 9

// We also cap the doubling, even though the standard doesn't say to.
// This has been 1.6 seconds for years, but for networks that
// experience moments of high RTT (such as 2G networks), this doesn't
// work well.
const int STUN_MAX_RTO = 8000;  // milliseconds, or 5 doublings

///////////////// StunRequestManager ////////////////////

StunRequestManager::StunRequestManager() : rtcbase::MemCheck("StunRequestManager") {}

StunRequestManager::~StunRequestManager() {
    while (_requests.begin() != _requests.end()) {
        StunRequest *request = _requests.begin()->second;
        _requests.erase(_requests.begin());
        delete request;
    }
}

void StunRequestManager::send(StunRequest* request) {
    send_delayed(request, 0);
}

void StunRequestManager::send_delayed(StunRequest* request, int delay) {
    request->set_manager(this);
    if (_requests.find(request->id()) != _requests.end()) {
        LOG(LS_WARNING) << "Stun request id is duplicate, ignore";
        return;
    }
    request->set_origin(_origin);
    request->construct();
    _requests[request->id()] = request;
    if (delay > 0) {

    } else {
        request->send_stun_message();
    }
}

void StunRequestManager::remove(StunRequest* request) {
    if (request->manager() != this) {
        return;
    }
    RequestMap::iterator iter = _requests.find(request->id());
    if (iter != _requests.end()) {
        if (iter->second == request) {
            _requests.erase(iter);
        }
    }
}

void StunRequestManager::clear() {
    std::vector<StunRequest*> requests;
    for (RequestMap::iterator i = _requests.begin(); i != _requests.end(); ++i) {
        requests.push_back(i->second);
    }

    for (uint32_t i = 0; i < requests.size(); ++i) {
        // StunRequest destructor calls Remove() which deletes requests
        // from |requests_|.
        delete requests[i];
    }
}

bool StunRequestManager::check_response(StunMessage* msg) {
    RequestMap::iterator iter = _requests.find(msg->transaction_id());
    if (iter == _requests.end()) {
        // TODO(pthatcher): Log unknown responses without being too spammy
        // in the logs.
        return false;
    }

    StunRequest* request = iter->second;
    if (msg->type() == get_stun_success_response_type(request->type())) {
        request->on_response(msg);
    } else if (msg->type() == get_stun_error_response_type(request->type())) {
        request->on_error_response(msg);
    } else {
        LOG(LS_WARNING) << "Received response with wrong type: " << msg->type()
            << " (expecting "
            << get_stun_success_response_type(request->type()) << ")";
        return false;
    }

    delete request;
    return true;
}

//////////////// StunRequest //////////////////////////

void resend_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    if (!data) {
        return;
    }
    
    StunRequest* r = (StunRequest*)(data);
    r->send_stun_message();
}

StunRequest::StunRequest(rtcbase::EventLoop* el)
    : rtcbase::MemCheck("StunRequest"), _count(0), 
    _timeout(false), _el(el), _manager(0), 
    _msg(new StunMessage()), _tstamp(0) 
{
    _resend_timer = _el->create_timer(resend_cb, (void*)this, true);
    _msg->set_transaction_ID(
            rtcbase::create_random_string(k_stun_transaction_id_length));
}

StunRequest::StunRequest(rtcbase::EventLoop* el, StunMessage* request)
    : rtcbase::MemCheck("StunRequest"), _count(0), 
    _timeout(false), _el(el), _manager(0), 
    _msg(request), _tstamp(0) 
{
    _resend_timer = _el->create_timer(resend_cb, (void*)this, true);
    _msg->set_transaction_ID(
            rtcbase::create_random_string(k_stun_transaction_id_length));
}

StunRequest::~StunRequest() {
    if (_resend_timer) {
        _el->delete_timer(_resend_timer);
        _resend_timer = nullptr;
    }
    
    if (_manager) {
        _manager->remove(this);
    }
    delete _msg;
}

void StunRequest::construct() {
    if (_msg->type() == 0) {
        if (!_origin.empty()) {
            _msg->add_attribute(rtcbase::make_unique<StunByteStringAttribute>(
                        STUN_ATTR_ORIGIN, _origin));
        }
        prepare(_msg);
    }
}

void StunRequest::on_sent() {
    _count += 1;
    int retransmissions = (_count - 1);
    if (retransmissions >= STUN_MAX_RETRANSMISSIONS) {
        _timeout = true;
    }
    LOG(LS_TRACE) << "Sent STUN request " << _count
        << "; resend delay = " << resend_delay();
}

int StunRequest::resend_delay() {
    if (_count == 0) {
        return 0;
    }
    int retransmissions = (_count - 1);
    int rto = STUN_INITIAL_RTO << retransmissions;
    return std::min(rto, STUN_MAX_RTO);
}

void StunRequest::set_manager(StunRequestManager* manager) {
    if (!_manager) {
        _manager = manager;
    }
}

void StunRequest::send_stun_message() {
    if (_manager == NULL) {
        return;
    }

    if (_timeout) {
        on_timeout();
        delete this;
        return;
    }
    
    _tstamp = rtcbase::time_millis();

    rtcbase::ByteBufferWriter buf;
    _msg->write(&buf);
    _manager->signal_send_packet(buf.data(), buf.length(), this);

    on_sent();
    
    if (_count > 1) {
        _el->stop_timer(_resend_timer);
    }
    // 启动重传定时器
    _el->start_timer(_resend_timer, resend_delay() * 1000);
}

int StunRequest::type() {
    if (_msg != NULL) {
        return _msg->type();
    }
    return -1;
}

const StunMessage* StunRequest::msg() const {
    return _msg;
}

int StunRequest::elapsed() const {
    return static_cast<int>(rtcbase::time_millis() - _tstamp);
}

} // namespace ice


