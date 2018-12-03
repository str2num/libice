/*
 *  Copyright (c) 2018 str2num. All Rights Reserved.
 *  Copyright (c) 2011, The WebRTC project authors. All rights reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */
  
/**
 * @file candidate_pair_interface.h
 * @author str2num
 * @brief 
 *  
 **/


#ifndef  __ICE_CANDIDATE_PAIR_INTERFACE_H_
#define  __ICE_CANDIDATE_PAIR_INTERFACE_H_

namespace ice {

class Candidate;

class CandidatePairInterface {
public:
    virtual ~CandidatePairInterface() {}

    virtual const Candidate& local_candidate() const = 0;
    virtual const Candidate& remote_candidate() const = 0;
};

}  // namespace ice

#endif  //__ICE_CANDIDATE_PAIR_INTERFACE_H_


