/*
 *  @file       MatterSubscribe.cpp
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

#include "MatterSubscribe.h"
#include "MatterError.h"
#include "MatterJsonUtils.h"
#include "MatterPublish.h"
#include "logger.h"
#include <platform/CHIPDeviceLayer.h>
#include <lib/core/ErrorStr.h>

// --- MatterSubscribe ---

MatterSubscribe::MatterSubscribe(
    chip::Controller::DeviceCommissioner* commissioner,
    chip::NodeId nodeId,
    chip::EndpointId endpointId,
    chip::ClusterId clusterId,
    chip::app::InteractionModelEngine* imEngine,
    uint16_t minInterval,
    uint16_t maxInterval,
    chip::ScopedNodeId peerId,
    chip::app::AttributePathParams* attrPaths,
    size_t numAttr,
    chip::app::EventPathParams* evPaths,
    size_t numEv)
    : MatterOperation(commissioner, nodeId),
      mImEngine(imEngine), mEndpointId(endpointId), mClusterId(clusterId),
      mMinInterval(minInterval), mMaxInterval(maxInterval), mPeerId(peerId),
      mAttrPaths(attrPaths), mNumAttr(numAttr),
      mEvPaths(evPaths), mNumEv(numEv),
      mCallback(std::make_unique<MatterSubscribeCallback>(this, nodeId, endpointId, clusterId))
{
}

MatterSubscribe::~MatterSubscribe()
{
    if (mAttrPaths)
        chip::Platform::MemoryFree(mAttrPaths);
    if (mEvPaths)
        chip::Platform::MemoryFree(mEvPaths);
}

void MatterSubscribe::OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                                                const chip::SessionHandle& /*sessionHandle*/)
{
    chip::app::ReadClient* readClient = chip::Platform::New<chip::app::ReadClient>(
        mImEngine, &exchangeMgr, *mCallback,
        chip::app::ReadClient::InteractionType::Subscribe);
    if (!readClient) {
        SetError(MatterError::ToInt(CHIP_ERROR_NO_MEMORY),
                 MatterError::ToMessage(MatterError::ToInt(CHIP_ERROR_NO_MEMORY)));
        Complete(false);
        return;
    }

    chip::app::ReadPrepareParams params;
    params.mMinIntervalFloorSeconds = mMinInterval;
    params.mMaxIntervalCeilingSeconds = mMaxInterval;
    params.mpAttributePathParamsList = mAttrPaths;
    params.mAttributePathParamsListSize = mNumAttr;
    params.mpEventPathParamsList = mEvPaths;
    params.mEventPathParamsListSize = mNumEv;

    // Paths are now owned by ReadClient via OnDeallocatePaths
    mAttrPaths = nullptr;
    mEvPaths = nullptr;

    CHIP_ERROR err = readClient->SendAutoResubscribeRequest(mPeerId, std::move(params));
    if (err != CHIP_NO_ERROR) {
        _LOG_ERROR("Subscribe: SendAutoResubscribeRequest failed: %s", chip::ErrorStr(err));
        chip::Platform::Delete(readClient);
        SetError(MatterError::ToInt(err), MatterError::ToMessage(MatterError::ToInt(err)));
        Complete(false);
        return;
    }

    mCallback->SetReadClient(readClient);
}

// --- MatterSubscribeCallback ---

MatterSubscribeCallback::MatterSubscribeCallback(MatterSubscribe* requestCtx, chip::NodeId nodeId,
                                     chip::EndpointId endpointId, chip::ClusterId clusterId)
    : mSubscribe(requestCtx), mNodeId(nodeId), mEndpointId(endpointId), mClusterId(clusterId)
{
    mAttributeArray = json_array();
    mEventArray = json_array();
}

MatterSubscribeCallback::~MatterSubscribeCallback()
{
    if (mAttributeArray)
        json_decref(mAttributeArray);
    if (mEventArray)
        json_decref(mEventArray);
}

void MatterSubscribeCallback::Shutdown()
{
    _LOG_INFO("Subscribe: shutting down node=%llu ep=%u cluster=0x%04x",
              (unsigned long long)mNodeId, mEndpointId, mClusterId);
    mDoneCallback = nullptr;
    if (mReadClient) {
        chip::Platform::Delete(mReadClient);
        mReadClient = nullptr;
    }
}

void MatterSubscribeCallback::OnSubscriptionEstablished(chip::SubscriptionId aSubscriptionId)
{
    _LOG_INFO("Subscribe: subscription established id=%u", static_cast<unsigned>(aSubscriptionId));
    mSubscriptionId = aSubscriptionId;
    if (mSubscribe) {
        mSubscribe->Notify(true);
        mSubscribe = nullptr;
    }
}

void MatterSubscribeCallback::OnAttributeData(const chip::app::ConcreteDataAttributePath& aPath, chip::TLV::TLVReader* apData,
                                         const chip::app::StatusIB& aStatus)
{
    _LOG_DEBUG("Subscribe: attribute node=%llu ep=%u cluster=0x%04x attr=0x%04x status=%u",
               (unsigned long long)mNodeId, aPath.mEndpointId, aPath.mClusterId, aPath.mAttributeId,
               static_cast<unsigned>(aStatus.mStatus));
    json_array_append_new(mAttributeArray,
        MatterJsonUtils::BuildAttributeEntry(aPath.mAttributeId, apData, static_cast<int>(aStatus.mStatus)));
}

void MatterSubscribeCallback::OnReportEnd()
{
    _LOG_DEBUG("Subscribe: report end node=%llu attrs=%zu events=%zu",
               (unsigned long long)mNodeId, json_array_size(mAttributeArray), json_array_size(mEventArray));
    if (json_array_size(mAttributeArray)) {
        MatterPublish::AttributeUpdate(mNodeId, mEndpointId, mClusterId, mAttributeArray);
        mAttributeArray = json_array();
    }
    if (json_array_size(mEventArray)) {
        MatterPublish::EventUpdate(mNodeId, mEndpointId, mClusterId, mEventArray);
        mEventArray = json_array();
    }
}

void MatterSubscribeCallback::OnEventData(const chip::app::EventHeader& aEventHeader, chip::TLV::TLVReader* apData,
                                     const chip::app::StatusIB* apStatus)
{
    _LOG_DEBUG("Subscribe: event node=%llu ep=%u cluster=0x%04x event=0x%04x",
               (unsigned long long)mNodeId, aEventHeader.mPath.mEndpointId, aEventHeader.mPath.mClusterId,
               aEventHeader.mPath.mEventId);
    json_array_append_new(mEventArray,
        MatterJsonUtils::BuildEventEntry(aEventHeader.mPath.mEventId, apData,
            apStatus ? static_cast<int>(apStatus->mStatus) : 0));
}

void MatterSubscribeCallback::OnError(CHIP_ERROR aError)
{
    _LOG_ERROR("Subscribe: error %s", chip::ErrorStr(aError));
    if (mSubscribe) {
        mSubscribe->SetError(MatterError::ToInt(aError), MatterError::ToMessage(MatterError::ToInt(aError)));
        mSubscribe->Notify(false);
        mSubscribe = nullptr;
    }
}

void MatterSubscribeCallback::OnDone(chip::app::ReadClient* apReadClient)
{
    _LOG_INFO("Subscribe: done (subscription ended) node=%llu ep=%u cluster=0x%04x",
              (unsigned long long)mNodeId, mEndpointId, mClusterId);
    mReadClient = nullptr;
    if (apReadClient)
        chip::Platform::Delete(apReadClient);
    if (mDoneCallback) {
        auto cb = std::move(mDoneCallback);
        chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
            auto* fn = reinterpret_cast<DoneCallback*>(arg);
            (*fn)();
            delete fn;
        }, reinterpret_cast<intptr_t>(new DoneCallback(std::move(cb))));
    }
}

void MatterSubscribeCallback::OnDeallocatePaths(chip::app::ReadPrepareParams&& aReadPrepareParams)
{
    if (aReadPrepareParams.mpAttributePathParamsList) {
        chip::Platform::MemoryFree(aReadPrepareParams.mpAttributePathParamsList);
        aReadPrepareParams.mpAttributePathParamsList = nullptr;
    }
    if (aReadPrepareParams.mpEventPathParamsList) {
        chip::Platform::MemoryFree(aReadPrepareParams.mpEventPathParamsList);
        aReadPrepareParams.mpEventPathParamsList = nullptr;
    }
}
