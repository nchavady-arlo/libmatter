/*
 *  @file       agw_matter_api.cpp
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

#include "MatterController.h"
#include "devif/agw_matter_api.h"
#include "logger.h"
#include <vector>

// --- Private helpers ---

static bool ValidateBootstrapInputs(const uint8_t *rcac, size_t rcac_len,
                                    const uint8_t *icac, size_t icac_len,
                                    const uint8_t *ipk, size_t ipk_len,
                                    const uint8_t *noc, size_t noc_len)
{
    if (!rcac || rcac_len == 0) {
        _LOG_ERROR("agw_matter_bootstrap: rcac is NULL or empty");
        return false;
    }
    if (!icac || icac_len == 0) {
        _LOG_ERROR("agw_matter_bootstrap: icac is NULL or empty");
        return false;
    }
    if (!ipk || ipk_len == 0) {
        _LOG_ERROR("agw_matter_bootstrap: ipk is NULL or empty");
        return false;
    }
    if (!noc || noc_len == 0) {
        _LOG_ERROR("agw_matter_bootstrap: noc is NULL or empty");
        return false;
    }
    return true;
}

static bool BuildResponsePayload(json_t *matterPayload, json_t *responsePayload)
{
    if (responsePayload) {
        json_t *outprops = json_object();
        if (outprops) {
            json_object_set_new(outprops, "matterPayload", json_deep_copy(matterPayload));
            json_object_set_new(responsePayload, "properties", outprops);
        }
    }
    return true;
}

// --- Public APIs (extern "C") ---
// Explicit extern "C" ensures C linkage even if the staging header is stale.

extern "C" {

// --- Lifecycle APIs ---

bool agw_matter_init(int log_level)
{
    return MatterController::singleton().Init(static_cast<log_levels_t>(log_level));
}

bool agw_matter_is_bootstrap_required(void)
{
    return MatterController::singleton().IsBootstrapRequired();
}

bool agw_matter_generate_bootstrap_csr(const char *csr_nonce, char **csr_pem, char **nocsr_elements)
{
    if (!csr_nonce || !csr_pem || !nocsr_elements) {
        _LOG_ERROR("agw_matter_generate_bootstrap_csr: invalid parameters");
        return false;
    }

    return MatterController::singleton().GenerateBootstrapCsr(csr_nonce, csr_pem, nocsr_elements);
}

bool agw_matter_bootstrap(const uint8_t *rcac, size_t rcac_len,
                          const uint8_t *icac, size_t icac_len,
                          const uint8_t *ipk, size_t ipk_len,
                          const uint8_t *noc, size_t noc_len)
{
    if (!ValidateBootstrapInputs(rcac, rcac_len, icac, icac_len, ipk, ipk_len, noc, noc_len))
        return false;

    return MatterController::singleton().Bootstrap(rcac, rcac_len, icac, icac_len, ipk, ipk_len, noc, noc_len);
}

bool agw_matter_start(void)
{
    return MatterController::singleton().Start();
}

void agw_matter_stop(void)
{
    MatterController::singleton().Stop();
}

bool agw_matter_is_running(void)
{
    return MatterController::singleton().IsRunning();
}

void agw_matter_set_loglevel(int log_level)
{
    MatterController::singleton().SetLogLevel(static_cast<log_levels_t>(log_level));
}

// --- Device control APIs ---

bool agw_matter_device_command(uint64_t nodeId, json_t *matterPayload, json_t *responsePayload)
{
    bool result = MatterController::singleton().DeviceCommand(nodeId, matterPayload);
    BuildResponsePayload(matterPayload, responsePayload);
    return result;
}

bool agw_matter_device_read(uint64_t nodeId, json_t *matterPayload, json_t *responsePayload)
{
    bool result = MatterController::singleton().DeviceRead(nodeId, matterPayload);
    BuildResponsePayload(matterPayload, responsePayload);
    return result;
}

bool agw_matter_device_write(uint64_t nodeId, json_t *matterPayload, json_t *responsePayload)
{
    bool result = MatterController::singleton().DeviceWrite(nodeId, matterPayload);
    BuildResponsePayload(matterPayload, responsePayload);
    return result;
}

bool agw_matter_device_subscribe(uint64_t nodeId, json_t *matterPayload, json_t *responsePayload)
{
    bool result = MatterController::singleton().DeviceSubscribe(nodeId, matterPayload);
    BuildResponsePayload(matterPayload, responsePayload);
    return result;
}

// --- Commissioning APIs ---

bool agw_matter_device_connect(uint64_t nodeId, int retryCount,
                               uint16_t minSubscriptionInt, uint16_t maxSubscriptionInt)
{
    std::vector<uint64_t> vec(1, nodeId);
    return MatterController::singleton().EstablishCaseSessions(vec, retryCount, minSubscriptionInt, maxSubscriptionInt);
}

bool agw_matter_device_delete(uint64_t nodeId)
{
    return MatterController::singleton().DeviceDelete(nodeId);
}

} // extern "C"
