/*
 *  @file       MatterPublish.cpp
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

#include "MatterPublish.h"
#include "MatterJsonUtils.h"
#include "logger.h"
#include "devif/agw_matter_api.h"

void MatterPublish::DeviceAnnounce(const DeviceInfo& info)
{
    json_auto_t* root = json_pack("{s:I, s:I, s:s, s:I, s:s, s:I, s:s, s:s}",
                                  "nodeId", (json_int_t)info.nodeId,
                                  "vendorId", (json_int_t)info.vendorId,
                                  "vendorName", info.vendorName.c_str(),
                                  "productId", (json_int_t)info.productId,
                                  "productName", info.productName.c_str(),
                                  "hwVersion", (json_int_t)info.hwVersion,
                                  "swVersion", info.swVersionString.c_str(),
                                  "serialNumber", info.serialNumber.c_str());
    if (!root) {
        _LOG_ERROR("DeviceAnnounce: json_pack failed for node %llu", (unsigned long long)info.nodeId);
        return;
    }

    json_t* epArray = json_array();
    for (const auto& [epId, desc] : info.endpoints) {
        json_t* deviceTypes = json_array();
        for (uint32_t dt : desc.deviceTypes)
            json_array_append_new(deviceTypes, json_integer((json_int_t)dt));

        json_t* epObj = json_pack("{s:i, s:o}",
                                  "endpointId", (int)epId,
                                  "deviceTypes", deviceTypes);

        json_t* clusters = json_array();
        for (uint32_t cid : desc.serverClusters)
            json_array_append_new(clusters, json_pack("{s:I, s:s}", "clusterId", (json_int_t)cid, "clusterRole", "server"));
        for (uint32_t cid : desc.clientClusters)
            json_array_append_new(clusters, json_pack("{s:I, s:s}", "clusterId", (json_int_t)cid, "clusterRole", "client"));

        json_object_set_new(epObj, "clusters", clusters);
        json_array_append_new(epArray, epObj);
    }
    json_object_set_new(root, "endpoints", epArray);
    agw_matter_device_announce_handler(info.nodeId, root);
}

void MatterPublish::AttributeUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* attributes)
{
    json_auto_t* payload = json_pack("{s:{s:i, s:I}, s:o}",
                                     "meta",
                                       "endpoint", (int)endpointId,
                                       "clusterId", (json_int_t)clusterId,
                                     "attribute", attributes);
    if (!payload) {
        _LOG_ERROR("AttributeUpdate: json_pack failed for node %llu", (unsigned long long)nodeId);
        return;
    }
    agw_matter_device_attribute_handler(nodeId, payload);
}

void MatterPublish::EventUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* events)
{
    json_auto_t* payload = json_pack("{s:{s:i, s:I}, s:o}",
                                     "meta",
                                       "endpoint", (int)endpointId,
                                       "clusterId", (json_int_t)clusterId,
                                     "event", events);
    if (!payload) {
        _LOG_ERROR("EventUpdate: json_pack failed for node %llu", (unsigned long long)nodeId);
        return;
    }
    agw_matter_device_event_handler(nodeId, payload);
}
