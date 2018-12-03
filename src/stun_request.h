/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file stun_request.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_STUN_REQUEST_H_
#define  __ICE_STUN_REQUEST_H_

#include <map>
#include <string>

#include <rtcbase/sigslot.h>
#include <rtcbase/event_loop.h>
#include <rtcbase/memcheck.h>
#include "stun.h"

namespace ice {

class StunRequest;

const int k_all_requests = 0;

// Manages a set of STUN requests, sending and resending until we receive a
// response or determine that the request has timed out.
class StunRequestManager : public rtcbase::MemCheck {
public:
    StunRequestManager();
    ~StunRequestManager();
    
    // Starts sending the given request (perhaps after a delay).
    void send(StunRequest* request);
    void send_delayed(StunRequest* request, int delay);
    
    // If |msg_type| is kAllRequests, sends all pending requests right away.
    // Otherwise, sends those that have a matching type right away.
    // Only for testing.
    //void Flush(int msg_type);

    // Returns true if at least one request with |msg_type| is scheduled for
    // transmission. For testing only.
    //bool HasRequest(int msg_type);

    // Removes a stun request that was added previously.  This will happen
    // automatically when a request succeeds, fails, or times out.
    void remove(StunRequest* request);

    // Removes all stun requests that were added previously.
    void clear();

    // Determines whether the given message is a response to one of the
    // outstanding requests, and if so, processes it appropriately.
    bool check_response(StunMessage* msg);
    //bool CheckResponse(const char* data, size_t size);

    bool empty() { return _requests.empty(); }

    // Set the Origin header for outgoing stun messages.
    void set_origin(const std::string& origin) { _origin = origin; }

    // Raised when there are bytes to be sent.
    rtcbase::Signal3<const void*, size_t, StunRequest*> signal_send_packet;

private:
    typedef std::map<std::string, StunRequest*> RequestMap;

    RequestMap _requests;
    std::string _origin;

    friend class StunRequest;
};

// Represents an individual request to be sent.  The STUN message can either be
// constructed beforehand or built on demand.
class StunRequest : public rtcbase::MemCheck {
public:
    StunRequest(rtcbase::EventLoop* el);
    StunRequest(rtcbase::EventLoop* el, StunMessage* request);
    virtual ~StunRequest();

    // Causes our wrapped StunMessage to be Prepared
    void construct();
    
    // The manager handling this request (if it has been scheduled for sending).
    StunRequestManager* manager() { return _manager; }

    // Returns the transaction ID of this request.
    const std::string& id() { return _msg->transaction_id(); }
    
    // the origin value
    const std::string& origin() const { return _origin; }
    void set_origin(const std::string& origin) { _origin = origin; }
    
    // Returns the STUN type of the request message.
    int type();
    
    // Returns a const pointer to |_msg|.
    const StunMessage* msg() const;

    // Time elapsed since last send (in ms)
    int elapsed() const;

protected:    
    // Fills in a request object to be sent.  Note that request's transaction ID
    // will already be set and cannot be changed.
    virtual void prepare(StunMessage* request) { (void)request; }
    
    // Called when the message receives a response or times out.
    virtual void on_response(StunMessage* response) { (void)response; }
    virtual void on_error_response(StunMessage* response) { (void)response; }
    virtual void on_timeout() {}
    // Called when the message is sent.
    virtual void on_sent();    
    // Returns the next delay for resends.
    virtual int resend_delay(); 
    
    friend void resend_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data);

private:
    void set_manager(StunRequestManager* manager);
    void send_stun_message();

protected:
    int _count;
    bool _timeout;
    std::string _origin;

private:
    rtcbase::EventLoop* _el; // not owned
    rtcbase::TimerWatcher* _resend_timer;
    StunRequestManager* _manager;
    StunMessage* _msg;
    int64_t _tstamp;
    
    friend class StunRequestManager; 
};

} // namespace ice

#endif  //__ICE_STUN_REQUEST_H_


