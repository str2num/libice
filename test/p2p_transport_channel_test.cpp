/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file p2p_transport_channel.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <rtcbase/logging.h>
#include <rtcbase/event_loop.h>
#include <ice/basic_port_allocator.h>
#include <ice/p2p_transport_channel.h>

static void test_maybe_start_gathering();

static void cron_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    (void)data;
}

class TestP2PtransportChannel {
public:
    TestP2PtransportChannel();
    
    void run();
    
    void set_ice_parameters(const ice::IceParameters& ice_param) {
        _channel->set_ice_parameters(ice_param);
    }
    
    void maybe_start_gathering() {
        _channel->start_gathering();
    }

private:
    rtcbase::EventLoop* _el;
    rtcbase::TimerWatcher* _cron_timer;

    std::unique_ptr<ice::PortAllocator> _port_allocator;
    std::unique_ptr<ice::PortAllocatorSession> _allocator_session;
    std::unique_ptr<ice::P2PTransportChannel> _channel;
};

TestP2PtransportChannel::TestP2PtransportChannel() {
    _el = new rtcbase::EventLoop((void*)this, false);
    _port_allocator.reset(new ice::BasicPortAllocator(_el));
    int port_allocator_flags = _port_allocator->flags();
    port_allocator_flags |= ice::PORTALLOCATOR_ENABLE_SHARED_SOCKET;
    _port_allocator->set_flags(port_allocator_flags);

    _channel.reset(new ice::P2PTransportChannel("audio", 1, _el, _port_allocator.get()));

    _cron_timer = _el->create_timer(cron_cb, (void*)this, true);
    _el->start_timer(_cron_timer, 1000000);
}

void TestP2PtransportChannel::run() {
    _el->run();
}

TestP2PtransportChannel* channel = new TestP2PtransportChannel();

void test_p2p_transport_channel() {
    test_maybe_start_gathering();
    channel->run();
}

static void test_maybe_start_gathering() {
    ice::IceParameters ice_param("ufrag1", "pw1fsfsdfsdfsdfsdfsdfsdsdfsd", false);
    channel->set_ice_parameters(ice_param);
    channel->maybe_start_gathering(); 
}


