/*
 *  @file       MatterController.h
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

    // Three-phase lifecycle
    bool Init();
    bool IsBootstrapRequired();
    bool GenerateBootstrapCsr(const char *csr_nonce, char **csr_pem, char **nocsr_elements);
    bool Bootstrap(const uint8_t *rcac, size_t rcac_len,
                   const uint8_t *icac, size_t icac_len,
                   const uint8_t *ipk, size_t ipk_len,
                   const uint8_t *noc, size_t noc_len);
    bool Start();
    void Stop();
    bool IsRunning() const;

    // Device control (split from ParseRequest)
    bool DeviceCommand(uint64_t nodeId, json_t* matterPayload);
    bool DeviceRead(uint64_t nodeId, json_t* matterPayload);
    bool DeviceWrite(uint64_t nodeId, json_t* matterPayload);
    bool DeviceSubscribe(uint64_t nodeId, json_t* matterPayload);

    // Commissioning
    bool CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid = nullptr, const char* password = nullptr);
    bool EstablishCaseSessions(const std::vector<uint64_t>& nodeIds, int retryCount,
                               uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt);
    bool DeviceDelete(uint64_t nodeId);

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
