/*
 *  @file       MatterDiscovery.h
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

#ifndef MATTER_DISCOVERY_H
#define MATTER_DISCOVERY_H

#include "MatterOperation.h"
#include "MatterPublish.h"
#include "MatterSubscribe.h"
#include <app/ReadClient.h>

class MatterDiscovery : public MatterOperation,
                        public chip::app::ReadClient::Callback
{
public:
    MatterDiscovery(chip::Controller::DeviceCommissioner* commissioner,
                    chip::NodeId nodeId);
    ~MatterDiscovery() override = default;

    // Full discovery flow: CASE -> read -> announce -> mandatory subscribe
    bool Discover(uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt);

    // Take ownership of the subscription callback after Discover() succeeds
    MatterSubscribeCallback::Ptr TakeSubscription() { return std::move(mSubscription); }

protected:
    // MatterOperation: CASE connected
    void OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                           const chip::SessionHandle& sessionHandle) override;

    // ReadClient::Callback: attribute data, error, done
    void OnAttributeData(const chip::app::ConcreteDataAttributePath& aPath,
                         chip::TLV::TLVReader* apData,
                         const chip::app::StatusIB& aStatus) override;
    void OnError(CHIP_ERROR aError) override;
    void OnDone(chip::app::ReadClient* apReadClient) override;

private:
    void SetupMandatorySubscription(uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt);
    void CollectBasicInfoAttr(chip::AttributeId attrId, chip::TLV::TLVReader* apData);
    void CollectDescriptorAttr(chip::EndpointId endpointId, chip::AttributeId attrId,
                               chip::TLV::TLVReader* apData);
    std::vector<uint32_t> ReadUint32Array(chip::TLV::TLVReader* reader) const;
    std::vector<uint32_t> ReadDeviceTypeList(chip::TLV::TLVReader* reader) const;

    MatterSubscribeCallback::Ptr mSubscription;
    DeviceInfo mDeviceInfo;
};

#endif // MATTER_DISCOVERY_H
