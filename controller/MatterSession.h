/*
 *  @file       MatterSession.h
 *  @author     Noel Chavady <nchavady@arlo.com>
 *
 * Copyright (c) 2026, Arlo Technologies, Inc.
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * Arlo Technologies, Inc. ("Confidential Information").  You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Arlo Technologies.
 */

#ifndef MATTER_SESSION_H
#define MATTER_SESSION_H

#include "MatterOperation.h"
#include "logger.h"

class MatterSession : public MatterOperation {
public:
    using MatterOperation::MatterOperation;

    bool Connect(int retryCount = 0)
    {
        for (int attempt = 0; attempt <= retryCount; ++attempt) {
            if (attempt > 0) {
                _LOG_INFO("CASE retry %d/%d for node %llu",
                          attempt, retryCount, (unsigned long long)NodeId());
                Reset();
            }
            Run();
            if (WaitForCompletion())
                return true;
        }
        return false;
    }

protected:
    void OnDeviceConnected(chip::Messaging::ExchangeManager& /*exchangeMgr*/,
                           const chip::SessionHandle& /*sessionHandle*/) override
    {
        Complete(true);
    }
};

#endif // MATTER_SESSION_H
