/***************************************************************************
 * 
 * Copyright (c) 2017 zuoyebang.com, Inc. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/
 
 
 
/**
 * @file ice_transport.h
 * @author zhouzhaopeng@zuoyebang.com
 * @version $Revision$ 
 * @brief 
 *  
 **/


#ifndef  __ICE_ICE_TRANSPORT_H_
#define  __ICE_ICE_TRANSPORT_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <rtcbase/constructor_magic.h>
#include <rtcbase/sigslot.h>
#include <rtcbase/event_loop.h>

#include "transport_description.h"
#include "candidate.h"

namespace ice {

class IceTransportChannel;

bool bad_transport_description(const std::string& desc, std::string* err_desc);

class IceTransport : public rtcbase::HasSlots<> {
public:
    IceTransport(const std::string& transport_name);
    ~IceTransport() override;

    const std::string& transport_name() const { return _transport_name; }
   
    bool add_channel(IceTransportChannel* channel, int component);
    bool remove_channel(int component);
    bool has_channels() const;

    bool ready_for_remote_candidates() const {
        return _local_description_set && _remote_description_set;
    } 
    
    bool set_local_transport_description(
            const TransportDescription& description,
            std::string* error_desc);
    bool set_remote_transport_description(
            const TransportDescription& description,
            std::string* error_desc);
    
    const TransportDescription* local_description() const {
        return _local_description.get();
    }
    
    const TransportDescription* remote_description() const {
        return _remote_description.get();
    }

private:
    // Pushes down the transport parameters from the local description, such
    // as the ICE ufrag and pwd.
    // Derived classes can override, but must call the base as well.
    virtual bool apply_local_transport_description(
            IceTransportChannel* channel,
            std::string* error_desc); 
    
    // Pushes down remote ice credentials from the remote description to the
    // transport channel.
    virtual bool apply_remote_transport_description(
            IceTransportChannel* channel,
            std::string* error_desc);
    
    // Negotiates the transport parameters based on the current local and remote
    // transport description, such as the ICE role to use, and whether DTLS
    // should be activated.
    // Derived classes can negotiate their specific parameters here, but must call
    // the base as well.
    virtual bool negotiate_transport_description(std::string* error_desc);
    
    // Pushes down the transport parameters obtained via negotiation.
    // Derived classes can set their specific parameters here, but must call the
    // base as well.
    //virtual bool apply_negotiated_transport_description(
      //      IceTransportChannel* channel,
        //    std::string* error_desc);

private:
    const std::string _transport_name;
    bool _need_ice_restart = false;

    std::unique_ptr<TransportDescription> _local_description;
    std::unique_ptr<TransportDescription> _remote_description;
    bool _local_description_set = false;
    bool _remote_description_set = false;
    
    // Candidate component => ICE channel
    std::map<int, IceTransportChannel*> _channels;

    RTC_DISALLOW_COPY_AND_ASSIGN(IceTransport);
};

} // namespace ice

#endif  //__ICE_ICE_TRANSPORT_H_


