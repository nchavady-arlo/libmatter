/*
 *  @file       MatterPublish.cpp
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

#include "MatterPublish.h"
#include "MatterJsonUtils.h"
#include "logger.h"
#include "matter_interface.h"

static json_t* BuildMeta(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId)
{
    return json_pack("{s:I,s:i,s:I}",
                     "nodeId", (json_int_t)nodeId,
                     "endpoint", (int)endpointId,
                     "clusterId", (json_int_t)clusterId);
}

static void Publish(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, const char* key, json_t* data)
{
    char resource[64];
    snprintf(resource, sizeof(resource), "matter/%013llu", (unsigned long long)nodeId);

    json_t* payload = json_object();
    json_object_set_new(payload, "meta", BuildMeta(nodeId, endpointId, clusterId));
    json_object_set_new(payload, key, data);

    CharAutoPtr dump(json_dumps(payload, JSON_COMPACT));
    _LOG_INFO("Publish: %s %s", resource, dump ? dump.get() : "{}");

    matter_event_handler(resource, payload);
}

void MatterPublish::AttributeUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* attributes)
{
    Publish(nodeId, endpointId, clusterId, "attribute", attributes);
}

void MatterPublish::EventUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* events)
{
    Publish(nodeId, endpointId, clusterId, "event", events);
}
