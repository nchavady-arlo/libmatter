/*
 *  @file       MatterOperation.h
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

#ifndef MATTER_OPERATION_H
#define MATTER_OPERATION_H

#include <controller/CHIPDeviceController.h>
#include <lib/core/CHIPError.h>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <string>

class MatterOperation {
public:
    MatterOperation(chip::Controller::DeviceCommissioner* commissioner, chip::NodeId nodeId);
    virtual ~MatterOperation() = default;

    MatterOperation(const MatterOperation&) = delete;
    MatterOperation& operator=(const MatterOperation&) = delete;

    chip::Controller::DeviceCommissioner* Commissioner() const { return mCommissioner; }
    chip::NodeId NodeId() const { return mNodeId; }

    void Run();
    bool WaitForCompletion(int timeoutSec = 60);

    void SetError(int code, const char* msg);
    int ErrorCode() const { return mErrorCode; }
    const std::string& ErrorMessage() const { return mErrorMessage; }

    chip::Callback::Callback<chip::OnDeviceConnected>& ConnectedCallback() { return mOnConnectedCb; }
    chip::Callback::Callback<chip::OnDeviceConnectionFailure>& FailureCallback() { return mOnFailureCb; }

protected:
    void Complete(bool ok);
    void Reset();

    virtual void OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                                   const chip::SessionHandle& sessionHandle) = 0;
    virtual void OnConnectionFailure(const chip::ScopedNodeId& peerId, CHIP_ERROR error);

    chip::Controller::DeviceCommissioner* mCommissioner;
    chip::NodeId mNodeId;
    bool mSuccess = false;
    bool mCompleted = false;
    std::mutex mMutex;
    std::condition_variable mCv;

private:
    static void OnDeviceConnectedTrampoline(void* context,
        chip::Messaging::ExchangeManager& exchangeMgr,
        const chip::SessionHandle& sessionHandle);
    static void OnConnectionFailureTrampoline(void* context,
        const chip::ScopedNodeId& peerId, CHIP_ERROR error);

    int mErrorCode = 0;
    std::string mErrorMessage;

    chip::Callback::Callback<chip::OnDeviceConnected> mOnConnectedCb;
    chip::Callback::Callback<chip::OnDeviceConnectionFailure> mOnFailureCb;
};

#endif // MATTER_OPERATION_H
