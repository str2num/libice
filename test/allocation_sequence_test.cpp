/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file allocation_sequence_test.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <rtcbase/event_loop.h>
#include <ice/basic_port_allocator.h>

void test_allocation_sequence_start();

void test_allocation_sequence() {
    test_allocation_sequence_start();
}

void test_allocation_sequence_start() {
    rtcbase::EventLoop* el = new rtcbase::EventLoop(NULL, false);
    std::unique_ptr<ice::PortAllocator> port_allocator(new ice::BasicPortAllocator(el));
    std::unique_ptr<ice::PortAllocatorSession> allocator_session;
    allocator_session = std::move(port_allocator->create_session("audio", 1, "test1", "pwd1", ""));

    rtcbase::IPAddress prefix;
    rtcbase::IP_from_string("115.29.20.0", &prefix);
    rtcbase::IPAddress ip;
    rtcbase::IP_from_string("115.29.102.225", &ip);
    rtcbase::Network network("ehth1", "ehth1", prefix, 20);
    network.add_IP(ip);
    network.set_type(rtcbase::ADAPTER_TYPE_ETHERNET);
    ice::AllocationSequence* sequence = new ice::AllocationSequence(
            (ice::BasicPortAllocatorSession*)allocator_session.get(), &network, NULL, 0);
    sequence->init();
    sequence->start();
}


