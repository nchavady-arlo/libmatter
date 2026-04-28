/*
 *  @file       MatterOperation.cpp
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

#include "MatterOperation.h"
#include "MatterError.h"
#include "logger.h"
#include <platform/CHIPDeviceLayer.h>
#include <lib/core/ErrorStr.h>

MatterOperation::MatterOperation(chip::Controller::DeviceCommissioner* commissioner, chip::NodeId nodeId)
    : mCommissioner(commissioner), mNodeId(nodeId),
      mOnConnectedCb(OnDeviceConnectedTrampoline, this),
      mOnFailureCb(OnConnectionFailureTrampoline, this)
{
}

void MatterOperation::Run()
{
    chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
        auto* ctx = reinterpret_cast<MatterOperation*>(arg);
        CHIP_ERROR err = ctx->Commissioner()->GetConnectedDevice(
            ctx->NodeId(), &ctx->ConnectedCallback(), &ctx->FailureCallback());
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("GetConnectedDevice failed for node %llu: %s",
                       (unsigned long long)ctx->NodeId(), chip::ErrorStr(err));
            ctx->SetError(MatterError::ToInt(err), MatterError::ToMessage(MatterError::ToInt(err)));
            ctx->Complete(false);
        }
    }, reinterpret_cast<intptr_t>(this));
}

void MatterOperation::Complete(bool ok)
{
    std::lock_guard<std::mutex> lock(mMutex);
    mSuccess = ok;
    mCompleted = true;
    mCv.notify_one();
}

bool MatterOperation::WaitForCompletion()
{
    std::unique_lock<std::mutex> lock(mMutex);
    mCv.wait(lock, [this] { return mCompleted; });
    return mSuccess;
}

void MatterOperation::Reset()
{
    std::lock_guard<std::mutex> lock(mMutex);
    mSuccess = false;
    mCompleted = false;
    mErrorCode = 0;
    mErrorMessage.clear();
}

void MatterOperation::SetError(int code, const char* msg)
{
    const bool isMatterStatus = (code >= 0x80 && code <= 0xFF);
    const bool haveMatterStatus = (mErrorCode >= 0x80 && mErrorCode <= 0xFF);
    if (isMatterStatus || !haveMatterStatus) {
        mErrorCode = code;
        mErrorMessage = msg ? msg : "";
    }
}

void MatterOperation::OnConnectionFailure(const chip::ScopedNodeId& peerId, CHIP_ERROR error)
{
    SetError(MatterError::ToInt(error), MatterError::ToMessage(MatterError::ToInt(error)));
    Complete(false);
}

void MatterOperation::OnDeviceConnectedTrampoline(void* context,
    chip::Messaging::ExchangeManager& exchangeMgr,
    const chip::SessionHandle& sessionHandle)
{
    auto* ctx = static_cast<MatterOperation*>(context);
    _LOG_INFO("CASE session established to node %llu", (unsigned long long)ctx->mNodeId);
    ctx->OnDeviceConnected(exchangeMgr, sessionHandle);
}

void MatterOperation::OnConnectionFailureTrampoline(void* context,
    const chip::ScopedNodeId& peerId, CHIP_ERROR error)
{
    auto* ctx = static_cast<MatterOperation*>(context);
    _LOG_ERROR("CASE session failed for node %llu: %s",
               (unsigned long long)peerId.GetNodeId(), chip::ErrorStr(error));
    ctx->OnConnectionFailure(peerId, error);
}

