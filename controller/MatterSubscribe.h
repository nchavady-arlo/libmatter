/*
 *  @file       MatterSubscribe.h
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

#ifndef MATTER_SUBSCRIBE_H
#define MATTER_SUBSCRIBE_H

#include "MatterOperation.h"
#include <app/ReadClient.h>
#include <app/ReadPrepareParams.h>
#include <app/InteractionModelEngine.h>
#include <jansson.h>
#include <functional>
#include <memory>

class MatterSubscribe;

class MatterSubscribeCallback : public chip::app::ReadClient::Callback
{
public:
    typedef std::unique_ptr<MatterSubscribeCallback> Ptr;
    typedef std::function<void()> DoneCallback;

    MatterSubscribeCallback(MatterSubscribe* subscribe, chip::NodeId nodeId,
                            chip::EndpointId endpointId, chip::ClusterId clusterId);
    ~MatterSubscribeCallback();

    void SetDoneCallback(DoneCallback cb) { mDoneCallback = std::move(cb); }
    void SetReadClient(chip::app::ReadClient* rc) { mReadClient = rc; }
    chip::SubscriptionId SubscriptionId() const { return mSubscriptionId; }

    void Shutdown();

    void OnSubscriptionEstablished(chip::SubscriptionId aSubscriptionId) override;
    void OnAttributeData(const chip::app::ConcreteDataAttributePath& aPath, chip::TLV::TLVReader* apData,
                         const chip::app::StatusIB& aStatus) override;
    void OnReportEnd() override;
    void OnEventData(const chip::app::EventHeader& aEventHeader, chip::TLV::TLVReader* apData,
                    const chip::app::StatusIB* apStatus) override;
    void OnError(CHIP_ERROR aError) override;
    void OnDone(chip::app::ReadClient* apReadClient) override;
    void OnDeallocatePaths(chip::app::ReadPrepareParams&& aReadPrepareParams) override;

private:
    MatterSubscribe* mSubscribe;
    chip::NodeId mNodeId;
    chip::EndpointId mEndpointId;
    chip::ClusterId mClusterId;
    json_t* mAttributeArray;
    json_t* mEventArray;
    DoneCallback mDoneCallback;
    chip::app::ReadClient* mReadClient = nullptr;
    chip::SubscriptionId mSubscriptionId = 0;
};

class MatterSubscribe : public MatterOperation {
public:
    typedef std::shared_ptr<MatterSubscribe> Ptr;
    MatterSubscribe(chip::Controller::DeviceCommissioner* commissioner,
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
                    size_t numEv);
    ~MatterSubscribe() override;

    void Notify(bool ok) { Complete(ok); }
    bool HasCallback() const { return mCallback != nullptr; }
    operator MatterSubscribeCallback::Ptr() { return std::move(mCallback); }

protected:
    void OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                           const chip::SessionHandle& sessionHandle) override;

private:
    chip::app::InteractionModelEngine* mImEngine;
    chip::EndpointId mEndpointId;
    chip::ClusterId mClusterId;
    uint16_t mMinInterval;
    uint16_t mMaxInterval;
    chip::ScopedNodeId mPeerId;
    chip::app::AttributePathParams* mAttrPaths;
    size_t mNumAttr;
    chip::app::EventPathParams* mEvPaths;
    size_t mNumEv;
    MatterSubscribeCallback::Ptr mCallback;
};

#endif // MATTER_SUBSCRIBE_H
