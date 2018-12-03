/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file worker.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICEAGENT_EXAM_WORKER_H_
#define  __ICEAGENT_EXAM_WORKER_H_

#include <queue>
#include <memory>

#include <rtcbase/event_loop.h>
#include <rtcbase/critical_section.h>
#include <ice/basic_port_allocator.h>

#include "peerconnection.h"

namespace exam {

class Worker {
public:
    enum {
        QUIT = 0,
        NEWCONNECTION = 1,
        REMOTE_ICE_SDP = 2,
        NEWMSG = 3
    };

    Worker();
    virtual ~Worker();
    
    int init();
    void run();
    int notify_new_connection(ice::IceRole role);
    int notify_remote_ice_sdp(const std::string& ice_sdp);
    int notify_new_msg(const std::string& content);

    friend void recv_notify(rtcbase::EventLoop* el, rtcbase::IOWatcher* w,
            int fd, int revents, void* data);

private:
    void _process_notify(int msg);
    void _stop();
    void _new_peerconnection();
    void _process_remote_ice_sdp();
    void _process_new_msg();

    int _notify(int msg);
    void _mq_push(void* data);
    void* _mq_pop();

private:
    rtcbase::EventLoop* _el; 
    ice::PortAllocator* _allocator;
    rtcbase::IOWatcher* _pipe_watcher;
    int _notify_recv_fd;
    int _notify_send_fd;

    rtcbase::CriticalSection _cs;
    std::queue<void*> _mq;

    std::unique_ptr<PeerConnection> _peerconnection;
};

} // namespace exam

#endif  //__ICEAGENT_EXAM_WORKER_H_


