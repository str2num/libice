/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file port_allocator_test.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <rtcbase/logging.h>
#include <rtcbase/event_loop.h>
#include <ice/basic_port_allocator.h>

static void test_start_getting_ports();

static void cron_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    (void)data;
}

class TestPortAllocator {
public:
    TestPortAllocator();
    
    void run();
    void start_getting_ports();
    
private:
    rtcbase::EventLoop* _el;
    rtcbase::TimerWatcher* _cron_timer;

    std::unique_ptr<ice::PortAllocator> _port_allocator;
    std::unique_ptr<ice::PortAllocatorSession> _allocator_session;
};

TestPortAllocator::TestPortAllocator() {
    _el = new rtcbase::EventLoop((void*)this, false);
    _port_allocator.reset(new ice::BasicPortAllocator(_el));
    int port_allocator_flags = _port_allocator->flags();
    port_allocator_flags |= ice::PORTALLOCATOR_ENABLE_SHARED_SOCKET;
    _port_allocator->set_flags(port_allocator_flags);

    _cron_timer = _el->create_timer(cron_cb, (void*)this, true);
    _el->start_timer(_cron_timer, 1000000);
}

void TestPortAllocator::run() {
    _el->run();
}

void TestPortAllocator::start_getting_ports() {
    _allocator_session = std::move(_port_allocator->create_session("audio", 1, "test1", "pwd1", ""));
    _allocator_session->start_getting_ports();
}

TestPortAllocator* tpa = new TestPortAllocator();

void test_port_allocator() {
    test_start_getting_ports();
    tpa->run();
}

static void test_start_getting_ports() {
    tpa->start_getting_ports();
}


