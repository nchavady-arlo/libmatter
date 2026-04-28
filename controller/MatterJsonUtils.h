/*
 *  @file       MatterJsonUtils.h
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

#ifndef MATTER_JSON_UTILS_H
#define MATTER_JSON_UTILS_H

#include <jansson.h>
#include <lib/core/CHIPError.h>
#include <lib/core/TLV.h>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>

struct CharAutoPtr : std::unique_ptr<char, decltype(&free)> {
    explicit CharAutoPtr(char* p) : std::unique_ptr<char, decltype(&free)>(p, free) {}
};

namespace MatterJsonUtils {

const char *GetString(json_t *obj, const char *key);
bool GetUInt32(json_t *obj, const char *key, uint32_t &out);
json_t *GetValue(json_t *obj);
bool ParseInteger(json_t *v, int64_t &out);

CHIP_ERROR EncodeCommandDataFieldsToTlv(json_t *commandData, std::vector<uint8_t> &out);
CHIP_ERROR CopyTlvFieldsIntoWriter(chip::TLV::TLVWriter &dst, const std::vector<uint8_t> &src);

json_t *TlvToJson(chip::TLV::TLVReader *reader);
const char *TlvDataType(chip::TLV::TLVReader *reader);

json_t *BuildAttributeEntry(uint32_t attributeId, chip::TLV::TLVReader *apData, int status);
json_t *BuildEventEntry(uint32_t eventId, chip::TLV::TLVReader *apData, int status);

} // namespace MatterJsonUtils

#endif // MATTER_JSON_UTILS_H
