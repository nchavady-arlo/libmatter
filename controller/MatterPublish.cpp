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

static json_t* BuildMeta(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId)
{
    return json_pack("{s:I,s:i,s:I}",
                     "nodeId", (json_int_t)nodeId,
                     "endpoint", (int)endpointId,
                     "clusterId", (json_int_t)clusterId);
}

void MatterPublish::AttributeUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* attributes)
{
    json_t* payload = json_object();
    json_object_set_new(payload, "meta", BuildMeta(nodeId, endpointId, clusterId));
    json_object_set_new(payload, "attribute", attributes);

    CharAutoPtr dump(json_dumps(payload, JSON_COMPACT));
    _LOG_INFO("AttributeUpdate: node=%llu %s", (unsigned long long)nodeId, dump ? dump.get() : "{}");

    agw_matter_device_attribute_handler(nodeId, payload);
    json_decref(payload);
}

void MatterPublish::EventUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* events)
{
    json_t* payload = json_object();
    json_object_set_new(payload, "meta", BuildMeta(nodeId, endpointId, clusterId));
    json_object_set_new(payload, "event", events);

    CharAutoPtr dump(json_dumps(payload, JSON_COMPACT));
    _LOG_INFO("EventUpdate: node=%llu %s", (unsigned long long)nodeId, dump ? dump.get() : "{}");

    agw_matter_device_event_handler(nodeId, payload);
    json_decref(payload);
}
