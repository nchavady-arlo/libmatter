/*
 *  @file       MatterCommand.h
 *  @author     Noel Chavady <nchavady@arlo.com>
 *
 * Copyright (c) 2025, Arlo Technologies, Inc.
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * Arlo Technologies, Inc. ("Confidential Information").  You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Arlo Technologies.
 */

#ifndef MATTER_COMMAND_H
#define MATTER_COMMAND_H

#include "MatterOperation.h"
#include "MatterError.h"
#include <functional>
#include <string>
#include <vector>

class MatterCommand : public MatterOperation {
public:
    typedef std::function<void(bool, int, const char*)> DoneCallback;

    MatterCommand(chip::Controller::DeviceCommissioner* comm, chip::NodeId nid,
                  chip::EndpointId eid, chip::ClusterId cid, uint32_t cmd,
                  std::vector<uint8_t> encodedTlv);

    chip::EndpointId EndpointId() const { return mEndpointId; }
    chip::ClusterId ClusterId() const { return mClusterId; }
    uint32_t CommandId() const { return mCommandId; }

protected:
    void OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                           const chip::SessionHandle& sessionHandle) override;

private:
    CHIP_ERROR InvokeCommand(chip::Messaging::ExchangeManager& exchangeMgr,
                             const chip::SessionHandle& sessionHandle,
                             const DoneCallback& done);

    chip::EndpointId mEndpointId;
    chip::ClusterId mClusterId;
    uint32_t mCommandId;
    std::vector<uint8_t> mEncodedTlv;
    uint8_t mAttempts = 0;

    int mScheduledErrorCode = 0;
    std::string mScheduledErrorMessage;
};

#endif // MATTER_COMMAND_H
