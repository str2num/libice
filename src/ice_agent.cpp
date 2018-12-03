/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file ice_agent.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include <algorithm>
#include <memory>
#include <assert.h>

#include "port.h"
#include "p2p_transport_channel.h"
#include "ice_agent.h"

namespace ice {

bool verify_candidate(const Candidate& cand, std::string* error) {
    // No address zero.
    if (cand.address().is_nil() || cand.address().is_any_IP()) {
        *error = "candidate has address of zero";
        return false;
    }

    // Disallow all ports below 1024, except for 80 and 443 on public addresses.
    int port = cand.address().port();
    if (cand.protocol() == TCP_PROTOCOL_NAME &&
            (cand.tcptype() == TCPTYPE_ACTIVE_STR || port == 0)) 
    {
        // Expected for active-only candidates per
        // http://tools.ietf.org/html/rfc6544#section-4.5 so no error.
        // Libjingle clients emit port 0, in "active" mode.
        return true;
    }
    if (port < 1024) {
        if ((port != 80) && (port != 443)) {
            *error = "candidate has port below 1024, but not 80 or 443";
            return false;
        }

        if (cand.address().is_private_IP()) {
            *error = "candidate has port of 80 or 443 with private IP address";
            return false;
        }
    }

    return true;
}

bool verify_candidates(const Candidates& candidates,
        std::string* error) 
{
    for (const Candidate& candidate : candidates) {
        if (!verify_candidate(candidate, error)) {
            return false;
        }
    }
    return true;
}

IceAgent::IceAgent(rtcbase::EventLoop* el, PortAllocator* port_allocator) 
    : rtcbase::MemCheck("IceAgent"), _el(el), _port_allocator(port_allocator)
{
    assert(el);
}

IceAgent::~IceAgent() {
    LOG_J(LS_TRACE, this) << "IceAgent destroyed";
}

void destory_cb(rtcbase::EventLoop* el, rtcbase::TimerWatcher* w, void* data) { 
    IceAgent* agent = (IceAgent*)data;
    agent->remove_all_streams();
    el->delete_timer(w);
    delete agent;
}

void IceAgent::destroy() {
    rtcbase::TimerWatcher* destroy_watcher = _el->create_timer(destory_cb, (void*)this, false);
    _el->start_timer(destroy_watcher, 1000);
}

void IceAgent::set_ice_config(const IceConfig& config) {
    _ice_config = config;
    for (auto& channel : _channels) {
        channel->set_ice_config(_ice_config);
    }
}

void IceAgent::set_ice_parameters(const IceParameters& ice_params) {
    _ice_params = ice_params;
    for (auto& channel : _channels) {
        channel->set_ice_parameters(ice_params);
    }
}

IceParameters IceAgent::get_ice_parameters() {
    return _ice_params;
}

bool IceAgent::set_ice_parameters(const std::string& transport_name, 
        int component, 
        const IceParameters& ice_params)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return false;
    }
    return channel->set_ice_parameters(ice_params);
}

void IceAgent::set_remote_ice_parameters(const IceParameters& ice_params) {
    _ice_params = ice_params;
    for (auto& channel : _channels) {
        channel->set_remote_ice_parameters(ice_params);
    }
}

bool IceAgent::set_remote_ice_parameters(const std::string& transport_name, 
        int component,
        const IceParameters& ice_params)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return false;
    }
    return channel->set_remote_ice_parameters(ice_params);
}

void IceAgent::set_ice_role(IceRole ice_role) {
    _ice_role = ice_role;
    for (auto& channel : _channels) {
        channel->set_ice_role(_ice_role);
    }
}

IceRole IceAgent::get_ice_role() {
    return _ice_role;
}

void IceAgent::set_remote_ice_mode(IceMode mode) {
    for (auto& channel : _channels) {
        channel->set_remote_ice_mode(mode);
    }
}

void IceAgent::set_ice_unique_ip(const std::string& ip) {
    _ice_unique_ip = ip;
    for (auto& channel : _channels) {
        channel->set_ice_unique_ip(_ice_unique_ip);
    }
}
 
bool IceAgent::add_stream(const std::string& transport_name,
        int component) 
{
    IceTransportChannel* existing_channel = get_transport_channel(transport_name, component);
    if (existing_channel) {
        LOG(LS_WARNING) << "Stream component already exist, transport_name: " << transport_name
            << ", component: " << component;
        return false;
    }
    
    IceTransportChannel* ice = new P2PTransportChannel(
            transport_name, component, _el, _port_allocator);

    ice->set_log_trace_id(get_log_trace_id());
    ice->set_ice_role(_ice_role);
    ice->set_ice_tiebreaker(_ice_tiebreaker);
    ice->set_ice_config(_ice_config);
    ice->set_log_trace_id(get_log_trace_id());
    ice->set_ice_unique_ip(_ice_unique_ip);

    // Connect to signal
    ice->signal_writable_state.connect(
            this, &IceAgent::on_channel_writable_state);
    ice->signal_receiving_state.connect(
            this, &IceAgent::on_channel_receiving_state);
    ice->signal_gathering_state.connect(
            this, &IceAgent::on_channel_gathering_state);
    ice->signal_candidate_gathered.connect(
            this, &IceAgent::on_channel_candidate_gathered);
    ice->signal_role_conflict.connect(
            this, &IceAgent::on_channel_role_conflict);
    ice->signal_state_changed.connect(
            this, &IceAgent::on_channel_state_changed);
    ice->signal_read_packet.connect(
            this, &IceAgent::on_channel_read);
    ice->signal_selected_candidate_pair_changed.connect(
            this, &IceAgent::on_selected_candidate_pair_changed);

    _channels.insert(_channels.end(), ice);
    // Adding a channel could cause aggregate state to change.
    update_aggregate_states();
    return true;
}

void IceAgent::start_gathering() {
    for (auto& channel : _channels) {
        channel->start_gathering();
    }
}

bool IceAgent::add_remote_candidates(const std::string& transport_name,
        const Candidates& candidates,
        std::string* err) 
{
    // Verify each candidate before passing down to the transport layer.
    if (!verify_candidates(candidates, err)) {
        return false;
    }
    
    for (const Candidate& candidate : candidates) {
        IceTransportChannel* channel = get_transport_channel(transport_name, 
                candidate.component());
        if (!channel) {
            *err = "Candidate has an unknown component: " + candidate.to_string() +
                " for content: " + transport_name;
            return false;
        }
        channel->add_remote_candidate(candidate);
    }
    return true;
}

int IceAgent::send_packet(const std::string& transport_name, int component,
        const char* data, size_t len, const rtcbase::PacketOptions& options)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return -1;
    }
    return channel->send_packet(data, len, options);  
}

int IceAgent::set_option(const std::string& transport_name, int component, 
            rtcbase::Socket::Option opt, int value)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return -1;
    }
    return channel->set_option(opt, value);
}

bool IceAgent::get_option(const std::string& transport_name, int component, 
        rtcbase::Socket::Option opt, int* value)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return false;
    }
    return channel->get_option(opt, value);
}

int IceAgent::get_rtt_estimate(const std::string& transport_name, int component) {
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return -1;
    }
    return channel->get_rtt_estimate();
}

int IceAgent::get_error(const std::string& transport_name, int component) {
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return 0;
    }
    return channel->get_error();
}

bool IceAgent::writable(const std::string& transport_name, int component) {
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return false;
    }
    return channel->writable();
}

IceTransportState IceAgent::get_state(const std::string& transport_name, 
        int component) 
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return IceTransportState::STATE_FAILED;
    }
    return channel->get_state(); 
}

IceGatheringState IceAgent::gathering_state(const std::string& transport_name, 
        int component)
{
    IceTransportChannel* channel = get_transport_channel(transport_name, component);
    if (!channel) {
        LOG_J(LS_WARNING, this) << "Transport channel not found, transport_name: " << transport_name
            << ", component: " << component;
        return IceGatheringState::k_ice_gathering_new;
    }
    return channel->gathering_state(); 
}

const char* IceAgent::get_ice_connection_state_str(IceConnectionState state) {
    switch (state) {
        case k_ice_connection_connecting:
            return "connecting";
        case k_ice_connection_failed:
            return "failed";
        case k_ice_connection_connected:
            return "connected";
        case k_ice_connection_completed:
            return "completed";
        default:
            return "unknown";
    }
}

std::string IceAgent::to_string() {
    std::stringstream ss;
    ss << "IceAgent[trace_id=" << get_log_trace_id()
       <<" ice_role=" << _ice_role << "-" 
       << get_ice_role_str(_ice_role)
       << " gathering_state=" << _gathering_state << "-" 
       << get_ice_gathering_state_str(_gathering_state)
       << " connection_state=" << _ice_connection_state << "-" 
       << get_ice_connection_state_str(_ice_connection_state)
       << "]";
    return ss.str();
}

std::vector<IceTransportChannel*>::iterator
IceAgent::get_transport_channel_iterator(
        const std::string& transport_name,
        int component) 
{
    return std::find_if(_channels.begin(), _channels.end(),
            [transport_name, component](IceTransportChannel* channel) 
            {
                return channel->transport_name() == transport_name &&
                channel->component() == component;
            });
}

std::vector<IceTransportChannel*>::const_iterator
IceAgent::get_transport_channel_iterator(
        const std::string& transport_name,
        int component) const 
{
    return std::find_if(_channels.begin(), _channels.end(),
            [transport_name, component](const IceTransportChannel* channel) 
            {
                return channel->transport_name() == transport_name &&
                channel->component() == component;
            });
}

IceTransportChannel* IceAgent::get_transport_channel(
        const std::string& transport_name,
        int component) 
{
    auto it = get_transport_channel_iterator(transport_name, component);
    return (it == _channels.end()) ? nullptr : *it;
}

const IceTransportChannel* IceAgent::get_transport_channel(
        const std::string& transport_name,
        int component) const
{
    auto it = get_transport_channel_iterator(transport_name, component);
    return (it == _channels.end()) ? nullptr : *it;
}

void IceAgent::remove_stream(
        const std::string& transport_name,
        int component) 
{
    auto iter = get_transport_channel_iterator(transport_name, component);
    if (iter == _channels.end()) {
        LOG(LS_WARNING) << "Attempting to delete " << transport_name
            << " TransportChannel " << component
            << ", which doesn't exist.";
        return; 
    }

    delete *iter;
    _channels.erase(iter);

    // Removing a channel could cause aggregate state to change.
    update_aggregate_states(); 
}

void IceAgent::remove_all_streams() {
    for (IceTransportChannel* channel : _channels) {
        delete channel;
    }
    _channels.clear(); 
}

void IceAgent::on_channel_writable_state(PacketTransportChannel* channel) {
    LOG_J(LS_TRACE, this) << channel->transport_name() << " TransportChannel "
        << channel->component() << " writability changed to "
        << channel->writable() << ".";
    signal_writable_state(channel->transport_name(), channel->component(), 
            channel->writable());
    update_aggregate_states();
}

void IceAgent::on_channel_receiving_state(PacketTransportChannel* channel) {
    (void)channel;
    update_aggregate_states();
}

void IceAgent::on_channel_gathering_state(
        IceTransportChannel* channel) 
{
    (void)channel;
    update_aggregate_states();
}

void IceAgent::on_channel_role_conflict(IceTransportChannel* channel) {
    (void)channel;
    // Note: since the role conflict is handled entirely on the network thread,
    // we don't need to worry about role conflicts occurring on two ports at once.
    // The first one encountered should immediately reverse the role.
    IceRole reversed_role = (_ice_role == ICEROLE_CONTROLLING)
        ? ICEROLE_CONTROLLED
        : ICEROLE_CONTROLLING;
    LOG_J(LS_TRACE, this) << "Got role conflict; switching to "
        << (reversed_role == ICEROLE_CONTROLLING ? "controlling"
                : "controlled")
        << " role.";
    set_ice_role(reversed_role);
}

void IceAgent::on_channel_state_changed(
        IceTransportChannel* channel) 
{
    LOG_J(LS_NOTICE, this) << channel->transport_name() << " TransportChannel "
        << channel->component()
        << " state changed. Check if state is complete.";
    signal_state_changed(channel->transport_name(), channel->component());
    update_aggregate_states();
}

void IceAgent::on_channel_read(PacketTransportChannel* channel, const char* data,
        size_t len, const rtcbase::PacketTime& pt, int flag)
{
    (void)flag;
    signal_read_packet(channel->transport_name(), channel->component(), data, len, pt);
}

void IceAgent::on_selected_candidate_pair_changed(
        IceTransportChannel* channel,
        CandidatePairInterface* selected_candidate_pair,
        int last_sent_packet_id,
        bool ready_to_send)
{
    signal_selected_candidate_pair_changed(channel->transport_name(),
            channel->component(),
            selected_candidate_pair,
            last_sent_packet_id,
            ready_to_send);
}

void IceAgent::update_aggregate_states() {
    IceConnectionState new_connection_state = k_ice_connection_connecting;
    IceGatheringState new_gathering_state = k_ice_gathering_new;
    bool any_receiving = false;
    bool any_failed = false;
    bool all_connected = !_channels.empty();
    bool all_completed = !_channels.empty();
    bool any_gathering = false;
    bool all_done_gathering = !_channels.empty();
    for (const auto& channel : _channels) {
        any_receiving = any_receiving || channel->receiving();
        any_failed = any_failed ||
            channel->get_state() == IceTransportState::STATE_FAILED;
        all_connected = all_connected && channel->writable();
        all_completed =
            all_completed && channel->writable() &&
            channel->get_state() == IceTransportState::STATE_COMPLETED &&
            channel->get_ice_role() == ICEROLE_CONTROLLING &&
            channel->gathering_state() == k_ice_gathering_complete;
        any_gathering =
            any_gathering || channel->gathering_state() != k_ice_gathering_new;
        all_done_gathering = all_done_gathering &&
            channel->gathering_state() == k_ice_gathering_complete;
    }

    if (any_failed) {
        new_connection_state = k_ice_connection_failed;
    } else if (all_completed) {
        new_connection_state = k_ice_connection_completed;
    } else if (all_connected) {
        new_connection_state = k_ice_connection_connected;
    }
    
    if (_ice_connection_state != new_connection_state) {
        _ice_connection_state = new_connection_state;
        signal_connection_state(new_connection_state);
    }

    if (_receiving != any_receiving) {
        _receiving = any_receiving;
        signal_receiving(any_receiving);
    }
    
    if (all_done_gathering) {
        new_gathering_state = k_ice_gathering_complete;
    } else if (any_gathering) {
        new_gathering_state = k_ice_gathering_gathering;
    }
    if (_gathering_state != new_gathering_state) {
        _gathering_state = new_gathering_state;
        signal_gathering_state(new_gathering_state);
    }
}

void IceAgent::on_channel_candidate_gathered(
        IceTransportChannel* channel,
        const Candidate& candidate) 
{
    // We should never signal peer-reflexive candidates.
    if (candidate.type() == PRFLX_PORT_TYPE) {
        return;
    }
    signal_candidate_gathered(channel->transport_name(), candidate);
}

} // namespace ice


