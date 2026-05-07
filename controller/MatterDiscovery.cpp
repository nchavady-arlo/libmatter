/*
 *  @file       MatterDiscovery.cpp
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

#include "MatterDiscovery.h"
#include "MatterPublish.h"
#include "logger.h"
#include <new>
#include <app/InteractionModelEngine.h>
#include <app/ReadPrepareParams.h>
#include <platform/CHIPDeviceLayer.h>
#include <lib/core/ErrorStr.h>

// Basic Information cluster (0x0028)
static constexpr chip::ClusterId kBasicInfoCluster      = 0x0028;
static constexpr chip::AttributeId kAttrVendorName      = 0x0001;
static constexpr chip::AttributeId kAttrVendorID        = 0x0002;
static constexpr chip::AttributeId kAttrProductName     = 0x0003;
static constexpr chip::AttributeId kAttrProductID       = 0x0004;
static constexpr chip::AttributeId kAttrHWVersion       = 0x0007;
static constexpr chip::AttributeId kAttrSWVersionString = 0x000A;
static constexpr chip::AttributeId kAttrSerialNumber    = 0x000F;

// Descriptor cluster (0x001D)
static constexpr chip::ClusterId kDescriptorCluster     = 0x001D;
static constexpr chip::AttributeId kAttrDeviceTypeList  = 0x0000;
static constexpr chip::AttributeId kAttrServerList      = 0x0001;
static constexpr chip::AttributeId kAttrClientList      = 0x0002;

// Basic Info events (cluster 0x0028, ep 0)
static constexpr chip::EventId kEventStartUp            = 0x0000;
static constexpr chip::EventId kEventShutDown           = 0x0001;
static constexpr chip::EventId kEventLeave              = 0x0002;

// Mandatory subscription clusters — wildcard endpoint, device ignores unsupported clusters
static constexpr chip::ClusterId kSubscribeClusters[] = {
    0x0006,  // On/Off
    0x0008,  // Level Control
    0x0101,  // Door Lock
    0x0201,  // Thermostat
    0x0202,  // Fan Control
    0x002F,  // Power Source (Battery)
    0x0045,  // Boolean State
    0x005C,  // Smoke CO Alarm
    0x0300,  // Color Control
    0x0406,  // Occupancy Sensing
};
static constexpr size_t kNumSubscribeClusters = sizeof(kSubscribeClusters) / sizeof(kSubscribeClusters[0]);

// --- MatterDiscovery ---

MatterDiscovery::MatterDiscovery(
    chip::Controller::DeviceCommissioner* commissioner,
    chip::NodeId nodeId)
    : MatterOperation(commissioner, nodeId)
{
    mDeviceInfo.nodeId = nodeId;
}

bool MatterDiscovery::Discover(uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt)
{
    Run();
    if (!WaitForCompletion())
        return false;
    SetupMandatorySubscription(minSubscriptionInt, maxSubscriptionInt);
    return true;
}

void MatterDiscovery::SetupMandatorySubscription(uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt)
{
    chip::app::InteractionModelEngine* imEngine = chip::app::InteractionModelEngine::GetInstance();
    if (!imEngine) {
        _LOG_WARNING("Discovery: cannot setup mandatory subscription — no IM engine");
        return;
    }

    chip::FabricIndex fabricIndex = mCommissioner->GetFabricIndex();
    chip::ScopedNodeId peerId(mNodeId, fabricIndex);

    // Subscribe to known application clusters with wildcard endpoint + wildcard attr
    auto* attrPaths = static_cast<chip::app::AttributePathParams*>(
        chip::Platform::MemoryAlloc(kNumSubscribeClusters * sizeof(chip::app::AttributePathParams)));
    if (!attrPaths) {
        _LOG_ERROR("Discovery: failed to allocate subscription attr paths");
        return;
    }
    for (size_t i = 0; i < kNumSubscribeClusters; i++) {
        new (&attrPaths[i]) chip::app::AttributePathParams(chip::kInvalidEndpointId, kSubscribeClusters[i]);
    }

    // Basic Info events: StartUp, ShutDown, Leave
    constexpr size_t kNumEvents = 3;
    auto* evPaths = static_cast<chip::app::EventPathParams*>(
        chip::Platform::MemoryCalloc(kNumEvents, sizeof(chip::app::EventPathParams)));
    if (!evPaths) {
        chip::Platform::MemoryFree(attrPaths);
        _LOG_ERROR("Discovery: failed to allocate subscription event paths");
        return;
    }
    new (&evPaths[0]) chip::app::EventPathParams(0, kBasicInfoCluster, kEventStartUp);
    new (&evPaths[1]) chip::app::EventPathParams(0, kBasicInfoCluster, kEventShutDown);
    new (&evPaths[2]) chip::app::EventPathParams(0, kBasicInfoCluster, kEventLeave);

    MatterSubscribe sub(mCommissioner, mNodeId, imEngine,
                         minSubscriptionInt, maxSubscriptionInt, peerId,
                         attrPaths, kNumSubscribeClusters, evPaths, kNumEvents);
    if (!sub.HasCallback()) {
        _LOG_ERROR("Discovery: failed to create subscription callback");
        return;
    }

    sub.Run();

    if (!sub.WaitForCompletion()) {
        _LOG_WARNING("Discovery: mandatory subscription failed for node %llu",
                     (unsigned long long)mNodeId);
        return;
    }

    mSubscription = sub;
    _LOG_INFO("Discovery: mandatory subscription established for node %llu", (unsigned long long)mNodeId);
}

// --- MatterOperation: CASE connected ---

void MatterDiscovery::OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                                         const chip::SessionHandle& sessionHandle)
{
    _LOG_INFO("Discovery: CASE connected for node %llu, reading Basic Info + Descriptor",
              (unsigned long long)mNodeId);

    chip::app::InteractionModelEngine* imEngine = chip::app::InteractionModelEngine::GetInstance();
    if (!imEngine) {
        _LOG_ERROR("Discovery: IM engine not available");
        Complete(false);
        return;
    }

    auto* readClient = chip::Platform::New<chip::app::ReadClient>(
        imEngine, &exchangeMgr, *this,
        chip::app::ReadClient::InteractionType::Read);
    if (!readClient) {
        _LOG_ERROR("Discovery: failed to allocate ReadClient");
        Complete(false);
        return;
    }

    // Build read paths:
    // Path 1: Basic Information (ep 0, cluster 0x0028, wildcard attr)
    // Path 2: Descriptor (wildcard ep, cluster 0x001D, wildcard attr)
    constexpr size_t kNumPaths = 2;
    auto* attrPaths = static_cast<chip::app::AttributePathParams*>(
        chip::Platform::MemoryAlloc(kNumPaths * sizeof(chip::app::AttributePathParams)));
    if (!attrPaths) {
        _LOG_ERROR("Discovery: failed to allocate attribute paths");
        chip::Platform::Delete(readClient);
        Complete(false);
        return;
    }

    new (&attrPaths[0]) chip::app::AttributePathParams(static_cast<chip::EndpointId>(0), kBasicInfoCluster);
    new (&attrPaths[1]) chip::app::AttributePathParams(chip::kInvalidEndpointId, kDescriptorCluster);

    chip::app::ReadPrepareParams params(sessionHandle);
    params.mpAttributePathParamsList = attrPaths;
    params.mAttributePathParamsListSize = kNumPaths;

    CHIP_ERROR err = readClient->SendRequest(params);

    if (err != CHIP_NO_ERROR) {
        _LOG_ERROR("Discovery: SendRequest failed: %s", chip::ErrorStr(err));
        chip::Platform::MemoryFree(attrPaths);
        chip::Platform::Delete(readClient);
        Complete(false);
        return;
    }
}

// --- ReadClient::Callback ---

void MatterDiscovery::OnAttributeData(
    const chip::app::ConcreteDataAttributePath& aPath,
    chip::TLV::TLVReader* apData,
    const chip::app::StatusIB& aStatus)
{
    if (aStatus.mStatus != chip::Protocols::InteractionModel::Status::Success) {
        _LOG_DEBUG("Discovery: attr ep=%u cluster=0x%04x attr=0x%04x status=%u (skipped)",
                   aPath.mEndpointId, aPath.mClusterId, aPath.mAttributeId,
                   static_cast<unsigned>(aStatus.mStatus));
        return;
    }
    if (!apData)
        return;

    _LOG_DEBUG("Discovery: attr ep=%u cluster=0x%04x attr=0x%04x type=%u",
               aPath.mEndpointId, aPath.mClusterId, aPath.mAttributeId,
               static_cast<unsigned>(apData->GetType()));

    if (aPath.mClusterId == kBasicInfoCluster && aPath.mEndpointId == 0) {
        CollectBasicInfoAttr(aPath.mAttributeId, apData);
    } else if (aPath.mClusterId == kDescriptorCluster) {
        CollectDescriptorAttr(aPath.mEndpointId, aPath.mAttributeId, apData);
    }
}

void MatterDiscovery::OnError(CHIP_ERROR aError)
{
    _LOG_ERROR("Discovery: read error for node %llu: %s",
               (unsigned long long)mNodeId, chip::ErrorStr(aError));
}

void MatterDiscovery::OnDone(chip::app::ReadClient* apReadClient)
{
    _LOG_INFO("Discovery: read complete for node %llu — vendor=\"%s\" product=\"%s\" serial=\"%s\" endpoints=%zu",
              (unsigned long long)mNodeId,
              mDeviceInfo.vendorName.c_str(), mDeviceInfo.productName.c_str(),
              mDeviceInfo.serialNumber.c_str(), mDeviceInfo.endpoints.size());

    MatterPublish::DeviceAnnounce(mDeviceInfo);

    if (apReadClient)
        chip::Platform::Delete(apReadClient);

    Complete(true);
}

void MatterDiscovery::OnDeallocatePaths(chip::app::ReadPrepareParams&& aReadPrepareParams)
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

// --- Attribute collection ---

void MatterDiscovery::CollectBasicInfoAttr(chip::AttributeId attrId,
                                            chip::TLV::TLVReader* apData)
{
    switch (attrId) {
    case kAttrVendorName: {
        chip::CharSpan val;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.vendorName.assign(val.data(), val.size());
        break;
    }
    case kAttrVendorID: {
        uint16_t val = 0;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.vendorId = val;
        break;
    }
    case kAttrProductName: {
        chip::CharSpan val;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.productName.assign(val.data(), val.size());
        break;
    }
    case kAttrProductID: {
        uint16_t val = 0;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.productId = val;
        break;
    }
    case kAttrHWVersion: {
        uint16_t val = 0;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.hwVersion = val;
        break;
    }
    case kAttrSWVersionString: {
        chip::CharSpan val;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.swVersionString.assign(val.data(), val.size());
        break;
    }
    case kAttrSerialNumber: {
        chip::CharSpan val;
        if (apData->Get(val) == CHIP_NO_ERROR)
            mDeviceInfo.serialNumber.assign(val.data(), val.size());
        break;
    }
    default:
        break;
    }
}

void MatterDiscovery::CollectDescriptorAttr(chip::EndpointId endpointId,
                                             chip::AttributeId attrId,
                                             chip::TLV::TLVReader* apData)
{
    EndpointDescriptor& ep = mDeviceInfo.endpoints[endpointId];

    switch (attrId) {
    case kAttrDeviceTypeList:
        ep.deviceTypes = ReadDeviceTypeList(apData);
        break;
    case kAttrServerList:
        ep.serverClusters = ReadUint32Array(apData);
        break;
    case kAttrClientList:
        ep.clientClusters = ReadUint32Array(apData);
        break;
    default:
        break;
    }
}

std::vector<uint32_t> MatterDiscovery::ReadUint32Array(chip::TLV::TLVReader* reader) const
{
    std::vector<uint32_t> result;
    if (!reader || reader->GetType() != chip::TLV::kTLVType_Array)
        return result;

    chip::TLV::TLVType container;
    if (reader->EnterContainer(container) != CHIP_NO_ERROR)
        return result;

    while (reader->Next() == CHIP_NO_ERROR) {
        uint32_t val = 0;
        if (reader->Get(val) == CHIP_NO_ERROR)
            result.push_back(val);
    }

    reader->ExitContainer(container);
    return result;
}

std::vector<uint32_t> MatterDiscovery::ReadDeviceTypeList(chip::TLV::TLVReader* reader) const
{
    // DeviceTypeList is an array of structs: { deviceType (tag 0), revision (tag 1) }
    // We only extract the deviceType field.
    std::vector<uint32_t> result;
    if (!reader || reader->GetType() != chip::TLV::kTLVType_Array)
        return result;

    chip::TLV::TLVType arrayContainer;
    if (reader->EnterContainer(arrayContainer) != CHIP_NO_ERROR)
        return result;

    while (reader->Next() == CHIP_NO_ERROR) {
        if (reader->GetType() != chip::TLV::kTLVType_Structure)
            continue;
        chip::TLV::TLVType structContainer;
        if (reader->EnterContainer(structContainer) != CHIP_NO_ERROR)
            continue;
        while (reader->Next() == CHIP_NO_ERROR) {
            chip::TLV::Tag tag = reader->GetTag();
            if (chip::TLV::IsContextTag(tag) && chip::TLV::TagNumFromTag(tag) == 0) {
                uint32_t deviceType = 0;
                if (reader->Get(deviceType) == CHIP_NO_ERROR)
                    result.push_back(deviceType);
            }
        }
        reader->ExitContainer(structContainer);
    }

    reader->ExitContainer(arrayContainer);
    return result;
}
