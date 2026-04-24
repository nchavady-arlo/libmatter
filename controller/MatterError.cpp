/*
 *  @file       MatterError.cpp
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

#include "MatterError.h"
#include <protocols/interaction_model/StatusCode.h>
#include <lib/core/ErrorStr.h>
#include <cstring>

struct ErrorEntry {
    MatterErrorCode code;
    const char *message;
};

static constexpr ErrorEntry kErrors[] = {
    { MatterErrorCode::kSuccess,            "Success"             },
    { MatterErrorCode::kOutOfMemory,        "Out of memory"       },
    { MatterErrorCode::kEncodeFailed,       "Encode failed"       },
    { MatterErrorCode::kEngineNotAvailable, "Engine not available" },
    { MatterErrorCode::kInvalidParams,      "Invalid parameters"  },
    { MatterErrorCode::kCommandTimeout,     "Command timeout"     },
    { MatterErrorCode::kSubscribeTimeout,   "Subscribe timeout"   },
    { MatterErrorCode::kCommandFailed,      "Command failed"      },
    { MatterErrorCode::kUnsupportedAction,  "Unsupported action"  },
};

const char *MatterError::ToMessage(MatterErrorCode code)
{
    for (const auto& [c, msg] : kErrors) {
        if (c == code) return msg;
    }
    return nullptr;
}

const char *MatterError::ToMessage(int code)
{
    /* Application-level error codes */
    const char *appMsg = ToMessage(static_cast<MatterErrorCode>(code));
    if (appMsg != nullptr)
        return appMsg;

    /* Matter Interaction Model status codes — use SDK enum values directly */
    using IMStatus = chip::Protocols::InteractionModel::Status;
    switch (static_cast<IMStatus>(code)) {
#define CHIP_IM_STATUS_CODE(name, spec_name, value) \
    case IMStatus::name: return #spec_name;
#include <protocols/interaction_model/StatusCodeList.h>
#undef CHIP_IM_STATUS_CODE
    }

    /* CHIP stack errors — use SDK ErrorStr, extract description after ": " prefix. */
    CHIP_ERROR chipErr = CHIP_ERROR(static_cast<uint32_t>(code));
    const char *full = chip::ErrorStr(chipErr, false);
    if (full) {
        const char *desc = strstr(full, ": ");
        if (desc && *(desc + 2))
            return desc + 2;
    }

    return "Unknown Error";
}

void MatterError::SetResult(json_t *matterPayload, MatterErrorCode code)
{
    SetResult(matterPayload, ToInt(code));
}

void MatterError::SetResult(json_t *matterPayload, int code)
{
    if (!matterPayload)
        return;
    json_t *result = json_pack("{s:i,s:s}", "code", code, "message", ToMessage(code));
    if (result)
        json_object_set_new(matterPayload, "result", result);
}
