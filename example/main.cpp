/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file main.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <unistd.h>

#include <rtcbase/base64.h>
#include <rtcbase/platform_thread.h>
#include <ice/basic_port_allocator.h>

#include "worker.h"
#include "peerconnection.h"

rtcbase::EventLoop* g_el = nullptr;
rtcbase::TimerWatcher* g_cron_timer = nullptr;
rtcbase::IOWatcher* g_stdio_watcher = nullptr;
exam::Worker* g_worker = nullptr;
int g_ice_role = 0;
bool g_is_connected = false;
int64_t g_connect_start = 0; 
bool g_is_timeout = true;
bool g_is_connected_succ_display = false;

const int CONN_TIMETOUT = 5000; // 5s

static void cron_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) {
    (void)el;
    (void)w;
    (void)data;
    
    if (rtcbase::time_millis() > g_connect_start + CONN_TIMETOUT && !g_is_connected && !g_is_timeout) {
        std::cout << "连接超时！\n请重新输入对端的ICE sdp:" << std::flush;
        g_is_timeout = true;
    }

    if (g_is_connected && !g_is_connected_succ_display) {
        std::cout << "连接成功，你现在可以输入消息和对方开始通信啦！" << std::endl;
        std::cout << "->:" << std::flush;
        g_is_connected_succ_display = true;
    }
}

static void stdio_cb(rtcbase::EventLoop* el, rtcbase::IOWatcher* w, int fd, 
        int revent, void* data) 
{
    (void)el;
    (void)w;
    (void)fd;
    (void)revent;
    (void)data;
   
    // 第一次输入的数据只能是ice_sdp
    std::string line;
    getline(std::cin, line);
    if (!g_is_connected) {
        if (line.empty()) {
            std::cout << "请输入对端的ICE sdp:" << std::flush;
            return;
        }
        std::cout << line << std::endl;
        std::cout << "正在连接，请稍后..." << std::endl;
        g_connect_start = rtcbase::time_millis();
        g_is_timeout = false;
        g_worker->notify_remote_ice_sdp(line);
    } else { // 文本消息 
        // 向对端发送消息
        if (!line.empty()) {
            g_worker->notify_new_msg(line);
            std::cout << line << "\n->:" << std::flush;
        } else {
            std::cout << "->:" << std::flush;
        }
    }
}

static void init() {
    // Log设置
    rtcbase::LogMessage::configure_logging("thread debug tstamp");
    rtcbase::LogMessage::set_log_to_stderr(false);  

    g_el = new rtcbase::EventLoop(nullptr, false);
    
    g_cron_timer = g_el->create_timer(cron_cb, nullptr, true);
    g_el->start_timer(g_cron_timer, 1000000);
    
    // 创建标准输入IO事件
    g_stdio_watcher = g_el->create_io_event(stdio_cb, nullptr);
    g_el->start_io_event(g_stdio_watcher, 0, rtcbase::EventLoop::READ);
}

static void start_worker(void* obj) {
    (void)obj;
    if (g_worker) {
        g_worker->run();
    }
}

static void init_worker() {
    g_worker = new exam::Worker();
    g_worker->init();
}

const char* USAGE = "Usage: ./peerconnection ice_role[0: controlling, 1: controlled]";
const int ICE_CONTROLLING = 0;
const int ICE_CONTROLLED = 1;

static void usage() {
    std::cout << USAGE << std::endl;
}

int main(int argc, char** argv) { 
    if (argc != 2) {
        usage();
        return -1;
    }
    
    g_ice_role = atoi(argv[1]);
    if (g_ice_role != ICE_CONTROLLING && g_ice_role != ICE_CONTROLLED) {
        usage();
        return -1;
    }

    init();
    init_worker();
    // 启动一个新线程
    rtcbase::PlatformThread thread(start_worker, nullptr, "worker"); 
    thread.start();
    
    g_worker->notify_new_connection((ice::IceRole)g_ice_role);

    g_el->run();

    return 0;
}


