/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file worker.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <unistd.h>

#include <rtcbase/logging.h>
#include <rtcbase/base64.h>

#include "worker.h"

namespace exam {

Worker::Worker() : _pipe_watcher(nullptr) {
    _el = new rtcbase::EventLoop((void*)this, false);
    _allocator = new ice::BasicPortAllocator(_el);
}

Worker::~Worker() {}

void recv_notify(rtcbase::EventLoop* el, rtcbase::IOWatcher* w,
        int fd, int revents, void* data)
{
    (void)el;
    (void)w;
    (void)revents;

    int msg; 
    if (read(fd, &msg, sizeof(int)) != sizeof(int)) {
        LOG(LS_FATAL) << "Read from pipe failed";
        return;
    }

    if (!data) {
        return;
    }

    Worker* worker = (Worker*)data;
    worker->_process_notify(msg);
}

void Worker::_process_notify(int msg) {
    switch (msg) {
        case QUIT:
            _stop();
            break;
        case NEWCONNECTION:
            _new_peerconnection();
            break;
        case REMOTE_ICE_SDP:
            _process_remote_ice_sdp();
            break;
        case NEWMSG:
            _process_new_msg();
            break;
        default:
            LOG(LS_WARNING) << "Unknown notify msg:" << msg;
            break;
    }
}

void Worker::_stop() {
    if (_pipe_watcher) {
        _el->delete_io_event(_pipe_watcher);
        _pipe_watcher = nullptr;
    }

    close(_notify_recv_fd);
    close(_notify_send_fd);
    _el->stop();
}

void Worker::_new_peerconnection() {
    ice::IceRole* prole = (ice::IceRole*)_mq_pop();
    if (!prole) {
        LOG(LS_WARNING) << "IceRole is nullptr";
        return;
    }

    _peerconnection.reset(new PeerConnection(_el, _allocator));
    _peerconnection->ice_agent()->add_stream("audio", 1);
    std::string ice_ufrag = rtcbase::create_random_string(ice::ICE_UFRAG_LENGTH);
    std::string ice_pwd = rtcbase::create_random_string(ice::ICE_PWD_LENGTH);
    ice::IceParameters ice_params(ice_ufrag, ice_pwd, false);
    _peerconnection->ice_agent()->set_ice_parameters(ice_params);
    _peerconnection->ice_agent()->set_ice_role(*prole);
    _peerconnection->ice_agent()->start_gathering();
    std::cout << "\nLocal candidate gathered finished." << std::endl;
    std::cout << "ICE sdp : " << std::endl;
    std::cout << _peerconnection->get_ice_sdp() << "\n";
    std::cout << "<----" << std::endl;
    std::cout << rtcbase::Base64::encode(_peerconnection->get_ice_sdp()) << "\n---->\n\n";
    if (*prole == ice::ICEROLE_CONTROLLING) {
        std::cout << "1. 当前的角色为ICE_CONTROLLING, 请再开启一个(ice role=ICE_CONTROLLED)的peerconnection进程终端\n";
    } else {
        std::cout << "1. 当前的角色为ICE_CONTROLLED, 请再开启一个(ice role=ICE_CONTROLLING)的peerconnection进程终端\n";
    }

    std::cout << "2. 按照提示将上面箭头中包含的candidate密文信息copy到新进程终端中\n\n";
    std::cout << "请输入对端的ICE sdp: " << std::flush;
    delete prole;
}

void Worker::_process_remote_ice_sdp() {
    char* psdp = (char*)_mq_pop();
    if (!psdp) {
        LOG(LS_WARNING) << "remote sdp is nullptr";
        return;
    }
    _peerconnection->set_remote_ice(psdp);
    delete[] psdp;
}

void Worker::_process_new_msg() {
    char* content = (char*)_mq_pop();
    if (!content) {
        LOG(LS_WARNING) << "content is nullptr";
        return;
    }
    _peerconnection->send_data(content, strlen(content));
    delete[] content;
}

int Worker::init() {
    int fds[2];
    if (pipe(fds)) {
        LOG(LS_FATAL) << "Can't create notify pipe";
        return -1;
    }

    _notify_recv_fd = fds[0];
    _notify_send_fd = fds[1];

    _pipe_watcher = _el->create_io_event(recv_notify, (void*)this);
    if (!_pipe_watcher) {
        LOG(LS_FATAL) << "Create pipe watcher failed";
        return -1;
    }
    _el->start_io_event(_pipe_watcher, _notify_recv_fd, rtcbase::EventLoop::READ);
    return 0;
}

void Worker::run() {
    LOG(LS_NOTICE) << "Worker run";
    _el->run();
}

int Worker::_notify(int msg) {
    int written = write(_notify_send_fd, &msg, sizeof(int));
    if (written != sizeof(int)) {
        LOG(LS_WARNING) << "Msg notify failed, msg: " << msg;
        return -1;
    }
    return 0;
}

void Worker::_mq_push(void* data) {
    rtcbase::CritScope lock(&_cs);
    _mq.push(data);
}

void* Worker::_mq_pop() {
    rtcbase::CritScope lock(&_cs);
    void *data = _mq.front();
    _mq.pop();
    return data;
}

int Worker::notify_new_connection(ice::IceRole role) {
    ice::IceRole* prole = new ice::IceRole;
    *prole = role;
    _mq_push(prole);
    return _notify(NEWCONNECTION);
}

int Worker::notify_remote_ice_sdp(const std::string& remote_ice_sdp) {
    char* psdp = new char[remote_ice_sdp.length() + 1];
    snprintf(psdp, remote_ice_sdp.length() + 1, "%s", remote_ice_sdp.c_str());
    _mq_push(psdp);
    return _notify(REMOTE_ICE_SDP);
}

int Worker::notify_new_msg(const std::string& content) {
    char* pcontent = new char[content.length() + 1];
    snprintf(pcontent, content.length() + 1, "%s", content.c_str());
    _mq_push(pcontent);
    return _notify(NEWMSG);
}

} // namespace exam



