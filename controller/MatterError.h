/*
 *  @file       MatterError.h
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

#ifndef _MATTER_ERROR_H_
#define _MATTER_ERROR_H_

#include <lib/core/CHIPError.h>
#include <jansson.h>

enum class MatterErrorCode : int {
    kSuccess            =  0,
    kOutOfMemory        = -1,
    kEncodeFailed       = -2,
    kEngineNotAvailable = -3,
    kInvalidParams      = -4,
    kCommandTimeout     = -5,
    kSubscribeTimeout   = -6,
    kCommandFailed      = -7,
    kUnsupportedAction  = -8,
};

class MatterError {
public:
    static constexpr int ToInt(MatterErrorCode code) noexcept {
        return static_cast<int>(code);
    }

    static constexpr int ToInt(CHIP_ERROR e) noexcept {
        return static_cast<int>(e.AsInteger());
    }

    static const char *ToMessage(MatterErrorCode code);
    static const char *ToMessage(int code);

    static void SetResult(json_t *matterPayload, MatterErrorCode code);
    static void SetResult(json_t *matterPayload, int code);
};

#endif // _MATTER_ERROR_H_
