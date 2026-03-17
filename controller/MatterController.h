/*
 *  @file       MatterController.h
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

#ifndef MATTER_CONTROLLER_H
#define MATTER_CONTROLLER_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#ifdef __cplusplus
#include <memory>
#include <string>
#include <vector>
#include "logger.h"

class MatterControllerImpl;

class MatterController {
public:
    MatterController();
    ~MatterController();

    bool Start(uint64_t fabricId, log_levels_t level);
    void Stop();
    void SetLogLevel(log_levels_t level);
    bool IsRunning() const;

    bool ParseRequest(const std::string& action, json_t* matterPayload);
    bool CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid = nullptr, const char* password = nullptr);
    bool EstablishCaseSessions(const std::vector<uint64_t>& nodeIds, int retryCount);

    static MatterController& singleton()
    {
        static MatterController instance;
        return instance;
    }

private:
    std::unique_ptr<MatterControllerImpl> mImpl;
};

#endif // __cplusplus

#endif // MATTER_CONTROLLER_H
