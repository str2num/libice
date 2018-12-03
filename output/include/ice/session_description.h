/***************************************************************************
 * 
 * Copyright (c) 2017 zuoyebang.com, Inc. All Rights Reserved
 * $Id$ 
 * 
 **************************************************************************/
 
 
 
/**
 * @file session_description.h
 * @author zhouzhaopeng@zuoyebang.com
 * @date 2017/08/18 10:41:32
 * @version $Revision$ 
 * @brief 
 *  
 **/


#ifndef  __ICE_SESSION_DESCRIPTION_H_
#define  __ICE_SESSION_DESCRIPTION_H_

#include <string>
#include <vector>

//#include "transport_info.h"
#include <rtcbase/constructor_magic.h>

namespace ice {

// Indicates whether a ContentDescription was an offer or an answer, as
// described in http://www.ietf.org/rfc/rfc3264.txt. CA_UPDATE
// indicates a jingle update message which contains a subset of a full
// session description
enum ContentAction {
    CA_OFFER, CA_PRANSWER, CA_ANSWER, CA_UPDATE
};

} // namespace rtcbase

#endif  //__ICE_SESSION_DESCRIPTION_H_


