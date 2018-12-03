/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file test.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include "test.h"

int main() {
    rtcbase::LogMessage::configure_logging("thread debug tstamp");
    rtcbase::LogMessage::set_log_to_stderr(true);

    //test_port_allocator();
    //test_allocation_sequence();
    test_p2p_transport_channel();
}


