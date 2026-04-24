/*
 *  @file       MatterPublish.h
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

#ifndef MATTER_PUBLISH_H
#define MATTER_PUBLISH_H

#include <stdint.h>
#include <jansson.h>

namespace MatterPublish {

void AttributeUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* attributes);
void EventUpdate(uint64_t nodeId, uint16_t endpointId, uint32_t clusterId, json_t* events);

} // namespace MatterPublish

#endif // MATTER_PUBLISH_H
