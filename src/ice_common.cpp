/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file ice_common.cpp
 * @author str2num
 * @brief 
 *  
 **/

#include "ice_common.h"

namespace ice {

const char* get_ice_role_str(IceRole role) {
    switch (role) {
        case ICEROLE_CONTROLLING:
            return "controlling";
        case ICEROLE_CONTROLLED:
            return "controlled";
        default:
            return "unknown";
    }
}

} // namespace ice


