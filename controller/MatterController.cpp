/*
 *  @file       MatterController.cpp
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
#include "MatterError.h"
#include "MatterJsonUtils.h"
#include "MatterCommand.h"
#include "MatterSession.h"
#include "MatterSubscribe.h"
#include "devif/agw_matter_api.h"
#include <platform/CHIPDeviceLayer.h>
#include <platform/ConnectivityManager.h>
#include <app/server/Server.h>
#include <lib/core/CHIPError.h>
#include <lib/core/ErrorStr.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/core/TLV.h>
#include <app/CommandSender.h>
#include <app/ReadClient.h>
#include <app/ReadPrepareParams.h>
#include <app/InteractionModelEngine.h>
#include <controller/CHIPDeviceController.h>
#include <controller/AutoCommissioner.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <controller/CHIPDeviceControllerFactory.h>
#include <controller/CommissioningDelegate.h>
#include <credentials/attestation_verifier/DefaultDeviceAttestationVerifier.h>
#include <credentials/attestation_verifier/DeviceAttestationVerifier.h>
#include <credentials/CHIPCert.h>
#include <credentials/PersistentStorageOpCertStore.h>
#include <credentials/GroupDataProviderImpl.h>
#include <crypto/DefaultSessionKeystore.h>
#include <crypto/PersistentStorageOperationalKeystore.h>
#include <platform/KvsPersistentStorageDelegate.h>
#include <platform/TestOnlyCommissionableDataProvider.h>
#include "MinimalDataModelProvider.h"
#include <lib/support/logging/CHIPLogging.h>
#include <credentials/DeviceAttestationConstructor.h>
#include <lib/support/Base64.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <atomic>
#include <future>
#include <mutex>
#include <map>
#include <tuple>
#include <vector>
#include <string>
#include <thread>
#include <cstdio>


// --- TestDeviceAttestationVerifier ---

class TestDeviceAttestationVerifier : public chip::Credentials::DeviceAttestationVerifier
{
public:
    void VerifyAttestationInformation(const AttestationInfo & info,
                                      chip::Callback::Callback<OnAttestationInformationVerification> * onCompletion) override
    {
        onCompletion->mCall(onCompletion->mContext, info, chip::Credentials::AttestationVerificationResult::kSuccess);
    }

    chip::Credentials::AttestationVerificationResult ValidateCertificationDeclarationSignature(const chip::ByteSpan & cmsEnvelopeBuffer,
                                                                            chip::ByteSpan & certDeclBuffer) override
    {
        return chip::Credentials::AttestationVerificationResult::kSuccess;
    }

    chip::Credentials::AttestationVerificationResult ValidateCertificateDeclarationPayload(const chip::ByteSpan & certDeclBuffer,
                                                                        const chip::ByteSpan & firmwareInfo,
                                                                        const chip::Credentials::DeviceInfoForAttestation & deviceInfo) override
    {
        return chip::Credentials::AttestationVerificationResult::kSuccess;
    }

    CHIP_ERROR VerifyNodeOperationalCSRInformation(const chip::ByteSpan & nocsrElementsBuffer,
                                                   const chip::ByteSpan & attestationChallengeBuffer,
                                                   const chip::ByteSpan & attestationSignatureBuffer,
                                                   const chip::Crypto::P256PublicKey & dacPublicKey,
                                                   const chip::ByteSpan & csrNonce) override
    {
        return CHIP_NO_ERROR;
    }

    void CheckForRevokedDACChain(const AttestationInfo & info,
                                 chip::Callback::Callback<OnAttestationInformationVerification> * onCompletion) override
    {
        onCompletion->mCall(onCompletion->mContext, info, chip::Credentials::AttestationVerificationResult::kSuccess);
    }
};

// --- MatterControllerImpl ---

class MatterControllerImpl : public chip::Controller::DevicePairingDelegate
{
public:
    enum class Action { kCommand, kRead, kWrite, kSubscribe, kUnknown };

    // Commissioning timeout: 4 minutes covers BLE scan + PASE + NOC + WiFi + 3x CASE retry (3×45s)
    static constexpr uint32_t kCommissionTimeoutMs = 4 * 60 * 1000;

    MatterControllerImpl() : mInitialized(false), mRunning(false), mCommissioningNodeId(0),
                             mCommissioningInProgress(false),
                             mTestVerifier(std::make_unique<TestDeviceAttestationVerifier>()) {}
    ~MatterControllerImpl() {}

    bool IsRunning() const { return mRunning; }

    // Run a callable on the CHIP event loop thread and block until it returns.
    // MUST NOT be called from the CHIP thread — will deadlock.
    // Usage: auto result = RunOnChipThread([](MatterControllerImpl* self) { return true; });
    template <typename Func>
    auto RunOnChipThread(Func&& fn) -> decltype(fn(std::declval<MatterControllerImpl*>())) {
        using ReturnType = decltype(fn(std::declval<MatterControllerImpl*>()));

        VerifyOrDie(!chip::DeviceLayer::PlatformMgr().IsChipStackLockedByCurrentThread());

        struct Context {
            MatterControllerImpl* self;
            Func* fn;
            std::promise<ReturnType> promise;
        };

        Context ctx{this, &fn, {}};
        auto future = ctx.promise.get_future();

        chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
            auto* c = reinterpret_cast<Context*>(arg);
            c->promise.set_value((*c->fn)(c->self));
        }, reinterpret_cast<intptr_t>(&ctx));

        return future.get();
    }

    void SetLogLevel(log_levels_t level) {
        chip::Logging::LogCategory result = chip::Logging::kLogCategory_Error;
        switch(level) {
            case LL_EMERG:
            case LL_ALERT:
            case LL_CRIT:
            case LL_ERROR:
                result = chip::Logging::kLogCategory_Error;
                break;
            case LL_WARNING:
            case LL_NOTICE:
            case LL_INFO:
                result = chip::Logging::kLogCategory_Progress;
                break;
            case LL_DEBUG:
                result = chip::Logging::kLogCategory_Detail;
                break;
            case LL_TRACE:
                result = chip::Logging::kLogCategory_Automation;
                break;
            case LL_MAX:
                result = chip::Logging::kLogCategory_Error;
                break;
        }
        chip::Logging::SetLogFilter(static_cast<uint8_t>(result));
    }

    // Phase 1: Platform + KVS initialization
    bool Init(log_levels_t level) {
        if (mInitialized) {
            _LOG_WARNING("Matter controller already initialized");
            return true;
        }

        SetLogLevel(level);

        CHIP_ERROR err = chip::Platform::MemoryInit();
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("Platform::MemoryInit failed: %s", chip::ErrorStr(err));
            return false;
        }

        err = chip::DeviceLayer::PlatformMgr().InitChipStack();
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("PlatformMgr().InitChipStack() failed: %s", chip::ErrorStr(err));
            return false;
        }

        chip::DeviceLayer::SetCommissionableDataProvider(&mCommissionableDataProvider);

        err = chip::DeviceLayer::PlatformMgr().StartEventLoopTask();
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("PlatformMgr().StartEventLoopTask() failed: %s", chip::ErrorStr(err));
            return false;
        }

        // Initialize storage delegates on CHIP thread
        bool initOk = RunOnChipThread([](MatterControllerImpl* self) -> bool {
            chip::DeviceLayer::ConnectivityMgr().SetBLEAdvertisingEnabled(false);
            chip::DeviceLayer::Internal::BLEMgrImpl().ConfigureBle(0, true);

            self->mStorage.Init(&chip::DeviceLayer::PersistedStorage::KeyValueStoreMgr());
            self->mOpKeystore.Init(&self->mStorage);
            self->mOpCertStore.Init(&self->mStorage);

            self->mGroupDataProvider.SetStorageDelegate(&self->mStorage);
            self->mGroupDataProvider.SetSessionKeystore(&self->mSessionKeystore);
            self->mGroupDataProvider.Init();
            return true;
        });

        if (!initOk) {
            _LOG_ERROR("Matter controller storage init failed on CHIP thread.");
            return false;
        }

        mInitialized = true;
        _LOG_INFO("Matter controller initialized (phase 1 complete).");
        return true;
    }

    // Phase 2: Check if bootstrap credentials exist in KVS
    bool IsBootstrapRequired() {
        if (!mInitialized) {
            _LOG_ERROR("IsBootstrapRequired called before Init");
            return true;
        }

        return RunOnChipThread([](MatterControllerImpl* self) -> bool {
            uint16_t dummy = 0;
            bool hasRcac = (self->mStorage.SyncGetKeyValue(self->kRcacStorageKey, nullptr, dummy) != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);
            bool hasNoc  = (self->mStorage.SyncGetKeyValue(self->kNocStorageKey,  nullptr, dummy) != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);
            bool hasIpk  = (self->mStorage.SyncGetKeyValue(self->kIpkStorageKey,  nullptr, dummy) != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

            bool required = !hasRcac || !hasNoc || !hasIpk;
            if (required)
                _LOG_INFO("Bootstrap required — RCAC=%s NOC=%s IPK=%s",
                          hasRcac ? "ok" : "missing", hasNoc ? "ok" : "missing", hasIpk ? "ok" : "missing");

            return required;
        });
    }

    // Phase 2a: Generate a keypair and CSR for bootstrap.
    // Input: base64-encoded csrNonce from backend.
    // Output: base64-encoded NOCSRElements TLV (caller must free with free()).
    bool GenerateBootstrapCsr(const char *csr_nonce, char **csr_pem, char **nocsr_elements) {
        if (!mInitialized) {
            _LOG_ERROR("GenerateBootstrapCsr called before Init");
            return false;
        }
        if (!csr_nonce || !csr_pem || !nocsr_elements) {
            _LOG_ERROR("GenerateBootstrapCsr: invalid parameters");
            return false;
        }

        // Decode base64 nonce
        uint16_t nonce_b64_len = static_cast<uint16_t>(strlen(csr_nonce));
        uint8_t nonceBuf[chip::Credentials::kExpectedAttestationNonceSize];
        uint16_t nonceLen = chip::Base64Decode(csr_nonce, nonce_b64_len, nonceBuf);
        if (nonceLen != chip::Credentials::kExpectedAttestationNonceSize) {
            _LOG_ERROR("GenerateBootstrapCsr: invalid nonce length %u (expected %zu)",
                       nonceLen, chip::Credentials::kExpectedAttestationNonceSize);
            return false;
        }
        chip::ByteSpan nonceSpan(nonceBuf, nonceLen);

        return RunOnChipThread([nonceSpan, csr_pem, nocsr_elements](MatterControllerImpl* self) -> bool {
            // Generate new operational keypair + DER-encoded CSR
            uint8_t csrBuf[chip::Crypto::kMIN_CSR_Buffer_Size];
            chip::MutableByteSpan csrSpan(csrBuf);

            CHIP_ERROR err = self->mOpKeystore.NewOpKeypairForFabric(self->kFabricIndex, csrSpan);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("GenerateBootstrapCsr: NewOpKeypairForFabric failed: %s", chip::ErrorStr(err));
                return false;
            }

            _LOG_INFO("GenerateBootstrapCsr: CSR generated (%zu bytes)", csrSpan.size());

            // Build PEM-encoded CSR: base64 of the DER CSR wrapped in PEM markers
            size_t csrB64Len = BASE64_ENCODED_LEN(csrSpan.size());
            // PEM format: header + base64 (with line breaks every 64 chars) + footer + null
            size_t pemMaxLen = 40 + csrB64Len + (csrB64Len / 64) + 40 + 1;
            char *pemOut = static_cast<char *>(malloc(pemMaxLen));
            if (!pemOut) {
                _LOG_ERROR("GenerateBootstrapCsr: out of memory (pem)");
                self->mOpKeystore.RevertPendingKeypair();
                return false;
            }

            std::vector<char> b64Tmp(csrB64Len + 1);
            uint16_t b64Written = chip::Base64Encode(csrSpan.data(),
                                                     static_cast<uint16_t>(csrSpan.size()),
                                                     b64Tmp.data());
            b64Tmp[b64Written] = '\0';

            // Build PEM with 64-char line wrapping
            size_t offset = snprintf(pemOut, pemMaxLen, "-----BEGIN CERTIFICATE REQUEST-----\n");
            for (uint16_t i = 0; i < b64Written; i += 64) {
                size_t lineLen = (b64Written - i > 64) ? 64 : (b64Written - i);
                if (offset + lineLen + 1 >= pemMaxLen) {
                    _LOG_ERROR("GenerateBootstrapCsr: PEM buffer overflow");
                    free(pemOut);
                    self->mOpKeystore.RevertPendingKeypair();
                    return false;
                }
                memcpy(pemOut + offset, b64Tmp.data() + i, lineLen);
                offset += lineLen;
                pemOut[offset++] = '\n';
            }
            offset += snprintf(pemOut + offset, pemMaxLen - offset, "-----END CERTIFICATE REQUEST-----\n");
            pemOut[offset] = '\0';
            *csr_pem = pemOut;

            _LOG_INFO("GenerateBootstrapCsr: PEM CSR built (%zu bytes)", offset);

            // Construct NOCSRElements TLV: {csr, csrNonce, vendor_reserved...}
            uint8_t nocsrBuf[chip::Credentials::kMaxRspLen];
            chip::MutableByteSpan nocsrSpan(nocsrBuf);
            chip::ByteSpan emptySpan;

            err = chip::Credentials::ConstructNOCSRElements(csrSpan, nonceSpan,
                                                            emptySpan, emptySpan, emptySpan,
                                                            nocsrSpan);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("GenerateBootstrapCsr: ConstructNOCSRElements failed: %s", chip::ErrorStr(err));
                free(*csr_pem); *csr_pem = nullptr;
                self->mOpKeystore.RevertPendingKeypair();
                return false;
            }

            _LOG_INFO("GenerateBootstrapCsr: NOCSRElements built (%zu bytes)", nocsrSpan.size());

            // Base64-encode the NOCSRElements
            size_t nocsrB64Len = BASE64_ENCODED_LEN(nocsrSpan.size());
            char *nocsrB64Out = static_cast<char *>(malloc(nocsrB64Len + 1));
            if (!nocsrB64Out) {
                _LOG_ERROR("GenerateBootstrapCsr: out of memory (nocsr)");
                free(*csr_pem); *csr_pem = nullptr;
                self->mOpKeystore.RevertPendingKeypair();
                return false;
            }

            uint16_t nocsrEncoded = chip::Base64Encode(nocsrSpan.data(),
                                                       static_cast<uint16_t>(nocsrSpan.size()),
                                                       nocsrB64Out);
            nocsrB64Out[nocsrEncoded] = '\0';
            *nocsr_elements = nocsrB64Out;

            _LOG_INFO("GenerateBootstrapCsr: success (pem=%d, nocsr_b64=%u)", offset, nocsrEncoded);
            return true;
        });
    }

    // Phase 2b: Install credentials into KVS (idempotent)
    // Safe to call again after partial write — overwrites any prior state.
    bool Bootstrap(const uint8_t *rcac, size_t rcac_len,
                   const uint8_t *icac, size_t icac_len,
                   const uint8_t *ipk, size_t ipk_len,
                   const uint8_t *noc, size_t noc_len) {
        if (!mInitialized) {
            _LOG_ERROR("Bootstrap called before Init");
            return false;
        }

        // Store raw X.509 DER certs + IPK under our own KVS keys.
        // We do NOT touch the CHIP SDK's cert store or keystore here —
        // SetupCommissioner in Start() will handle all SDK-internal state
        // (cert store, keystore, fabric table) in one atomic operation.
        CHIP_ERROR err;

        err = mStorage.SyncSetKeyValue(kRcacStorageKey, rcac, static_cast<uint16_t>(rcac_len));
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("Bootstrap: failed to store RCAC: %s", chip::ErrorStr(err));
            return false;
        }

        err = mStorage.SyncSetKeyValue(kIcacStorageKey, icac, static_cast<uint16_t>(icac_len));
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("Bootstrap: failed to store ICAC: %s", chip::ErrorStr(err));
            return false;
        }

        err = mStorage.SyncSetKeyValue(kNocStorageKey, noc, static_cast<uint16_t>(noc_len));
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("Bootstrap: failed to store NOC: %s", chip::ErrorStr(err));
            return false;
        }

        err = mStorage.SyncSetKeyValue(kIpkStorageKey, ipk, static_cast<uint16_t>(ipk_len));
        if (err != CHIP_NO_ERROR) {
            _LOG_ERROR("Bootstrap: failed to store IPK: %s", chip::ErrorStr(err));
            return false;
        }

        _LOG_INFO("Bootstrap: credentials stored — RCAC=%zu, ICAC=%zu, NOC=%zu, IPK=%zu",
                  rcac_len, icac_len, noc_len, ipk_len);
        return true;
    }

    // Phase 3: Setup commissioner and begin operation
    bool Start() {
        if (!mInitialized) {
            _LOG_ERROR("Start called before Init");
            return false;
        }

        if (mRunning) {
            _LOG_WARNING("Matter controller already running");
            return true;
        }

        bool result = RunOnChipThread([](MatterControllerImpl* self) -> bool {
            // Init DeviceControllerFactory — this loads the FabricTable from
            // persistent storage (any fabric created by a previous Start).
            chip::Controller::FactoryInitParams factoryParams;
            factoryParams.systemLayer = &chip::DeviceLayer::SystemLayer();
            factoryParams.fabricIndependentStorage = &self->mStorage;
            factoryParams.dataModelProvider = chip::app::MinimalDataModelProviderInstance();
            factoryParams.opCertStore = &self->mOpCertStore;
            factoryParams.sessionKeystore = &self->mSessionKeystore;
            factoryParams.operationalKeystore = &self->mOpKeystore;
            factoryParams.groupDataProvider = &self->mGroupDataProvider;
            factoryParams.bleLayer = chip::DeviceLayer::ConnectivityMgr().GetBleLayer();

            CHIP_ERROR initErr = chip::Controller::DeviceControllerFactory::GetInstance().Init(factoryParams);
            if (initErr != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to init DeviceControllerFactory: %s", chip::ErrorStr(initErr));
                return false;
            }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            if (self->mOpCredsIssuer.Initialize(self->mStorage) != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to init OpCredsIssuer");
                return false;
            }
#pragma GCC diagnostic pop

            chip::Controller::SetupParams setupParams;
            setupParams.pairingDelegate = self;
            setupParams.operationalCredentialsDelegate = &self->mOpCredsIssuer;
            setupParams.enableServerInteractions = true;
            setupParams.controllerVendorId = chip::VendorId::TestVendor1;
            setupParams.deviceAttestationVerifier = self->mTestVerifier.get();
            setupParams.defaultCommissioner = &self->mAutoCommissioner;

            // Check if FabricTable already has our fabric (from a previous
            // successful Start). If so, reference it by index. Otherwise,
            // load raw X.509 DER certs from our custom KVS keys and let
            // SetupCommissioner create the fabric from scratch.
            const auto * fabricTable = chip::Controller::DeviceControllerFactory::GetInstance().GetSystemState()->Fabrics();
            const auto * fabricInfo = (fabricTable != nullptr) ? fabricTable->FindFabricWithIndex(self->kFabricIndex) : nullptr;

            if (fabricInfo != nullptr) {
                _LOG_INFO("Using existing fabric at index %u", static_cast<unsigned>(self->kFabricIndex));
                setupParams.fabricIndex.SetValue(self->kFabricIndex);
            } else {
                _LOG_INFO("No existing fabric — loading bootstrap certs from KVS");

                // Load raw X.509 DER certs from our custom KVS keys
                uint8_t rcacBuf[chip::Controller::kMaxCHIPDERCertLength];
                uint8_t icacBuf[chip::Controller::kMaxCHIPDERCertLength];
                uint8_t nocBuf[chip::Controller::kMaxCHIPDERCertLength];
                uint16_t rcacSize = sizeof(rcacBuf), icacSize = sizeof(icacBuf), nocSize = sizeof(nocBuf);

                if (self->mStorage.SyncGetKeyValue(self->kRcacStorageKey, rcacBuf, rcacSize) != CHIP_NO_ERROR ||
                    self->mStorage.SyncGetKeyValue(self->kIcacStorageKey, icacBuf, icacSize) != CHIP_NO_ERROR ||
                    self->mStorage.SyncGetKeyValue(self->kNocStorageKey,  nocBuf,  nocSize)  != CHIP_NO_ERROR) {
                    _LOG_ERROR("Failed to load bootstrap certs from KVS");
                    return false;
                }

                _LOG_INFO("Loaded bootstrap certs: RCAC=%u, ICAC=%u, NOC=%u", rcacSize, icacSize, nocSize);

                setupParams.controllerRCAC = chip::ByteSpan(rcacBuf, rcacSize);
                setupParams.controllerICAC = chip::ByteSpan(icacBuf, icacSize);
                setupParams.controllerNOC  = chip::ByteSpan(nocBuf, nocSize);
            }

            CHIP_ERROR err = chip::Controller::DeviceControllerFactory::GetInstance().SetupCommissioner(setupParams, self->mCommissioner);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to setup commissioner: %s", chip::ErrorStr(err));
                return false;
            }

            _LOG_INFO("Commissioner initialized on fabric index %d", self->mCommissioner.GetFabricIndex());

            // Load IPK from KVS (stored by Bootstrap)
            uint8_t ipkBuf[chip::Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
            uint16_t ipkSize = sizeof(ipkBuf);
            CHIP_ERROR ipkLoadErr = self->mStorage.SyncGetKeyValue(self->kIpkStorageKey, ipkBuf, ipkSize);
            if (ipkLoadErr != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to load IPK from KVS: %s", chip::ErrorStr(ipkLoadErr));
                return false;
            }
            chip::ByteSpan ipkSpan(ipkBuf, ipkSize);

            uint64_t compressedFabricId = self->mCommissioner.GetCompressedFabricId();
            uint8_t compressedFabricIdBuffer[sizeof(uint64_t)];
            chip::Encoding::BigEndian::Put64(compressedFabricIdBuffer, compressedFabricId);
            chip::ByteSpan compressedFabricIdSpan(compressedFabricIdBuffer);

            CHIP_ERROR ipkErr = chip::Credentials::SetSingleIpkEpochKey(&self->mGroupDataProvider, self->mCommissioner.GetFabricIndex(), ipkSpan, compressedFabricIdSpan);
            if (ipkErr != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to set IPK: %s", chip::ErrorStr(ipkErr));
                return false;
            }

            _LOG_INFO("IPK set for fabric index %d", self->mCommissioner.GetFabricIndex());
            return true;
        });

        if (!result) {
            _LOG_ERROR("Matter controller start failed on CHIP thread.");
            return false;
        }

        mRunning = true;
        _LOG_INFO("Matter controller started (phase 3 complete).");
        return true;
    }

    void Stop() {
        if (!mRunning)
            return;

        mRunning = false;

        CHIP_ERROR stopErr = chip::DeviceLayer::PlatformMgr().StopEventLoopTask();
        if (stopErr != CHIP_NO_ERROR) {
            _LOG_ERROR("PlatformMgr().StopEventLoopTask() failed: %s", chip::ErrorStr(stopErr));
            return;
        }

        chip::DeviceLayer::PlatformMgr().LockChipStack();
        {
            std::lock_guard<std::mutex> lock(mSubscribeCallbacksMutex);
            for (auto& [key, cb] : mSubscribeCallbacks)
                cb->Shutdown();
            mSubscribeCallbacks.clear();
        }
        mCommissioner.Shutdown();
        chip::DeviceLayer::PlatformMgr().UnlockChipStack();

        chip::Controller::DeviceControllerFactory::GetInstance().Shutdown();

        mInitialized = false;
        _LOG_INFO("Matter controller stopped.");
    }

    bool DeviceCommand(const std::string& actionStr, json_t* matterPayload) {
        if (!mRunning) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kCommandFailed);
            return false;
        }

        json_int_t nodeIdVal = 0, endpointVal = 0, clusterIdVal = 0;
        if (json_unpack(matterPayload, "{s:{s:I,s:I,s:I}}",
                                       "meta",
                                       "nodeId", &nodeIdVal,
                                       "endpoint", &endpointVal,
                                       "clusterId", &clusterIdVal) != 0) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kInvalidParams);
            return false;
        }

        chip::NodeId nodeId       = static_cast<chip::NodeId>(nodeIdVal);
        chip::EndpointId endpointId = static_cast<chip::EndpointId>(endpointVal);
        chip::ClusterId clusterId = static_cast<chip::ClusterId>(clusterIdVal);

        return ParseCommand(nodeId, endpointId, clusterId, matterPayload);
    }

    bool DeviceRead(const std::string& actionStr, json_t* matterPayload) {
        if (!mRunning) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kCommandFailed);
            return false;
        }
        // Stub — will be implemented in a later chunk
        _LOG_ERROR("DeviceRead: not yet implemented");
        MatterError::SetResult(matterPayload, MatterErrorCode::kUnsupportedAction);
        return false;
    }

    bool DeviceWrite(const std::string& actionStr, json_t* matterPayload) {
        if (!mRunning) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kCommandFailed);
            return false;
        }
        // Stub — will be implemented in a later chunk
        _LOG_ERROR("DeviceWrite: not yet implemented");
        MatterError::SetResult(matterPayload, MatterErrorCode::kUnsupportedAction);
        return false;
    }

    bool DeviceSubscribe(const std::string& actionStr, json_t* matterPayload) {
        if (!mRunning) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kCommandFailed);
            return false;
        }

        json_int_t nodeIdVal = 0, endpointVal = 0, clusterIdVal = 0;
        if (json_unpack(matterPayload, "{s:{s:I,s:I,s:I}}",
                                       "meta",
                                       "nodeId", &nodeIdVal,
                                       "endpoint", &endpointVal,
                                       "clusterId", &clusterIdVal) != 0) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kInvalidParams);
            return false;
        }

        chip::NodeId nodeId       = static_cast<chip::NodeId>(nodeIdVal);
        chip::EndpointId endpointId = static_cast<chip::EndpointId>(endpointVal);
        chip::ClusterId clusterId = static_cast<chip::ClusterId>(clusterIdVal);

        return ParseSubscribe(nodeId, endpointId, clusterId, matterPayload);
    }

    /**
     * Complete a pending commissioning attempt — cancels the watchdog timer.
     * Must be called on the CHIP thread (timer callback / delegate callback).
     */
    void CompleteCommissioning(chip::NodeId nodeId, bool success, const char *error) {
        if (!mCommissioningInProgress.exchange(false))
            return; /* already completed / timed out */

        chip::DeviceLayer::SystemLayer().CancelTimer(OnCommissioningTimeout, this);

        _LOG_INFO("Commissioning result for node %llu: %s%s%s",
                  (unsigned long long)nodeId,
                  success ? "success" : "failed",
                  error ? " — " : "", error ? error : "");
    }

    static void OnCommissioningTimeout(chip::System::Layer *, void *appState) {
        auto *self = static_cast<MatterControllerImpl *>(appState);
        chip::NodeId nodeId = self->mCommissioningNodeId;

        _LOG_ERROR("Commissioning timeout for node %llu — no completion callback received",
                   (unsigned long long)nodeId);

        self->CompleteCommissioning(nodeId, false, "Commissioning timeout");
    }

    bool CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid, const char* password) {
        mCommissioningNodeId = static_cast<chip::NodeId>(nodeId);
        mCommissioningInProgress = true;

        struct CommissionContext {
            MatterControllerImpl* controller;
            chip::NodeId nodeId;
            std::string payload;
            std::string ssid;
            std::string password;
        };

        auto* ctx = new CommissionContext{this, static_cast<chip::NodeId>(nodeId), payload,
                                         ssid ? ssid : "", password ? password : ""};

        chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
            auto* ctx = reinterpret_cast<CommissionContext*>(arg);

            /* Start the watchdog timer before PairDevice */
            chip::DeviceLayer::SystemLayer().StartTimer(
                chip::System::Clock::Milliseconds32(kCommissionTimeoutMs),
                OnCommissioningTimeout, ctx->controller);

            if (!ctx->ssid.empty() && !ctx->password.empty()) {
                chip::Controller::CommissioningParameters params;
                params.SetWiFiCredentials(chip::Controller::WiFiCredentials(
                    chip::ByteSpan(reinterpret_cast<const uint8_t*>(ctx->ssid.data()), ctx->ssid.size()),
                    chip::ByteSpan(reinterpret_cast<const uint8_t*>(ctx->password.data()), ctx->password.size())));
                ctx->controller->mCommissioner.PairDevice(ctx->nodeId, ctx->payload.c_str(), params);
            } else {
                ctx->controller->mCommissioner.PairDevice(ctx->nodeId, ctx->payload.c_str());
            }

            delete ctx;
        }, reinterpret_cast<intptr_t>(ctx));
        return true;
    }

    bool EstablishCaseSessions(const std::vector<uint64_t>& nodeIds, int retryCount) {
        if (!mRunning)
            return false;

        if (nodeIds.empty()) {
            _LOG_INFO("EstablishCaseSessions: no node IDs, nothing to do");
            return true;
        }

        std::vector<std::thread> threads;
        threads.reserve(nodeIds.size());

        for (auto id : nodeIds) {
            threads.emplace_back([this, id, retryCount]() {
                MatterSession session(&mCommissioner, id);
                if (!session.Connect(retryCount))
                    _LOG_ERROR("EstablishCaseSessions: failed for node %llu after %d attempt(s)",
                               (unsigned long long)id, retryCount + 1);
            });
        }

        for (auto& t : threads)
            t.join();

        _LOG_INFO("EstablishCaseSessions: completed for %zu device(s)", nodeIds.size());
        return true;
    }

    bool DeviceDelete(uint64_t nodeId) {
        // Stub — will be implemented in Chunk 6 (CMFW-26658)
        _LOG_INFO("DeviceDelete: stub for node %llu (Chunk 6)", (unsigned long long)nodeId);
        return false;
    }

    typedef std::tuple<chip::NodeId, chip::EndpointId, chip::ClusterId> SubscribeKey;

    void AddSubscribeCallback(chip::NodeId nodeId, chip::EndpointId endpointId,
                              chip::ClusterId clusterId, MatterSubscribeCallback::Ptr cb) {
        std::lock_guard<std::mutex> lock(mSubscribeCallbacksMutex);
        SubscribeKey key(nodeId, endpointId, clusterId);

        auto it = mSubscribeCallbacks.find(key);
        if (it != mSubscribeCallbacks.end()) {
            auto iter = std::move(it->second);
            mSubscribeCallbacks.erase(it);
            iter->SetDoneCallback(nullptr);
            chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
                auto* p = reinterpret_cast<MatterSubscribeCallback*>(arg);
                p->Shutdown();
                delete p;
            }, reinterpret_cast<intptr_t>(iter.release()));
        }

        cb->SetDoneCallback([this, key]() {
            std::lock_guard<std::mutex> lock(mSubscribeCallbacksMutex);
            mSubscribeCallbacks.erase(key);
        });
        mSubscribeCallbacks.emplace(key, std::move(cb));
    }

    // DevicePairingDelegate
    void OnStatusUpdate(chip::Controller::DevicePairingDelegate::Status status) override {
        _LOG_INFO("Pairing Status Update: %d", status);
    }

    void OnPairingComplete(CHIP_ERROR error) override {
        if (error != CHIP_NO_ERROR) {
            _LOG_ERROR("Pairing Failed: %s", chip::ErrorStr(error));
            CompleteCommissioning(mCommissioningNodeId, false, chip::ErrorStr(error));
        } else {
            _LOG_INFO("Pairing Complete");
        }
    }

    void OnCommissioningStatusUpdate(chip::PeerId peerId, chip::Controller::CommissioningStage stageCompleted, CHIP_ERROR error) override {
        _LOG_INFO("Commissioning stage '%s' completed: %s", chip::Controller::StageToString(stageCompleted), chip::ErrorStr(error));
    }

    void OnCommissioningFailure(chip::PeerId peerId, CHIP_ERROR error, chip::Controller::CommissioningStage stageFailed,
                                chip::Optional<chip::Credentials::AttestationVerificationResult> additionalErrorInfo) override {
        _LOG_ERROR("Commissioning failed at stage '%s': %s", chip::Controller::StageToString(stageFailed), chip::ErrorStr(error));
        CompleteCommissioning(mCommissioningNodeId, false, chip::ErrorStr(error));
    }

    void OnCommissioningComplete(chip::NodeId nodeId, CHIP_ERROR error) override {
        if (error != CHIP_NO_ERROR) {
            _LOG_ERROR("Commissioning Failed: %s", chip::ErrorStr(error));
            CompleteCommissioning(nodeId, false, chip::ErrorStr(error));
            return;
        }

        _LOG_INFO("Commissioning Complete for NodeId: %llu", (unsigned long long)nodeId);

        /* Build minimal deviceInfo and fire announce callback.
         * Full interrogation (Basic Info / Descriptor reads) is added in Chunk 5. */
        json_t *deviceInfo = json_pack("{s:I}", "nodeId", (json_int_t)nodeId);
        if (deviceInfo) {
            agw_matter_device_announce_handler(nodeId, deviceInfo);
            json_decref(deviceInfo);
        }

        CompleteCommissioning(nodeId, true, NULL);
    }

private:
    bool ParseCommand(chip::NodeId nodeId, chip::EndpointId endpointId, chip::ClusterId clusterId,
                      json_t* matterPayload) {
        json_t* j_command = json_object_get(matterPayload, "command");
        if (j_command == nullptr) {
            _LOG_ERROR("Missing 'command' in payload");
            MatterError::SetResult(matterPayload, MatterErrorCode::kInvalidParams);
            return false;
        }
        json_int_t commandIdVal = json_integer_value(j_command);

        json_t* j_commandData = json_object_get(matterPayload, "commandData");
        return SendCommand(nodeId, endpointId, clusterId, static_cast<uint32_t>(commandIdVal), j_commandData, matterPayload);
    }

    bool ParseSubscribe(chip::NodeId nodeId, chip::EndpointId endpointId, chip::ClusterId clusterId,
                        json_t* matterPayload) {
        json_int_t minIntervalVal = 1, maxIntervalVal = 300;
        json_unpack(matterPayload, "{s?I,s?I}", "minInterval", &minIntervalVal, "maxInterval", &maxIntervalVal);
        uint16_t minInterval = static_cast<uint16_t>(minIntervalVal <= 0 ? 1 : (minIntervalVal > 65535 ? 65535 : minIntervalVal));
        uint16_t maxInterval = static_cast<uint16_t>(maxIntervalVal <= 0 ? 300 : (maxIntervalVal > 65535 ? 65535 : maxIntervalVal));

        std::vector<uint32_t> attributeIds;
        std::vector<uint32_t> eventIds;
        json_t* json_attrs = json_object_get(matterPayload, "attribute");
        if (json_attrs && json_is_array(json_attrs)) {
            size_t n = json_array_size(json_attrs);
            attributeIds.reserve(n);
            for (size_t i = 0; i < n; i++) {
                json_t* json_elem = json_array_get(json_attrs, i);
                if (json_elem && json_is_integer(json_elem))
                    attributeIds.push_back(static_cast<uint32_t>(json_integer_value(json_elem)));
            }
        }
        json_t* json_event = json_object_get(matterPayload, "event");
        if (json_event && json_is_array(json_event)) {
            size_t n = json_array_size(json_event);
            eventIds.reserve(n);
            for (size_t i = 0; i < n; i++) {
                json_t* json_elem = json_array_get(json_event, i);
                if (json_elem && json_is_integer(json_elem))
                    eventIds.push_back(static_cast<uint32_t>(json_integer_value(json_elem)));
            }
        }
        return Subscribe(nodeId, endpointId, clusterId, minInterval, maxInterval, attributeIds, eventIds, matterPayload);
    }

    bool SendCommand(chip::NodeId nodeId, chip::EndpointId endpointId, chip::ClusterId clusterId,
                     uint32_t commandId, json_t* commandData, json_t* matterPayload) {
        _LOG_INFO("Sending command to node %llu (endpoint=%u, cluster=0x%04x, command=%u)",
                  (unsigned long long)nodeId, endpointId, clusterId, commandId);

        std::vector<uint8_t> encodedTlv;
        CHIP_ERROR encErr = MatterJsonUtils::EncodeCommandDataFieldsToTlv(commandData, encodedTlv);
        if (encErr != CHIP_NO_ERROR) {
            _LOG_ERROR("Failed to encode commandData to TLV: %s", chip::ErrorStr(encErr));
            MatterError::SetResult(matterPayload, MatterErrorCode::kEncodeFailed);
            return false;
        }

        MatterCommand cmd(&mCommissioner, nodeId, endpointId, clusterId, commandId, std::move(encodedTlv));

        cmd.Run();

        if (!cmd.WaitForCompletion()) {
            _LOG_ERROR("Matter command failed for node %llu: code=0x%02x %s",
                       (unsigned long long)nodeId, cmd.ErrorCode(),
                       cmd.ErrorMessage().empty() ? "unknown" : cmd.ErrorMessage().c_str());
            MatterError::SetResult(matterPayload, cmd.ErrorCode());
            return false;
        }

        _LOG_INFO("Matter command succeeded for node %llu", (unsigned long long)nodeId);
        MatterError::SetResult(matterPayload, MatterErrorCode::kSuccess);
        return true;
    }

    bool Subscribe(chip::NodeId nodeId, chip::EndpointId endpointId, chip::ClusterId clusterId,
                   uint16_t minInterval, uint16_t maxInterval,
                   const std::vector<uint32_t>& attributeIds, const std::vector<uint32_t>& eventIds,
                   json_t* matterPayload) {
        chip::app::InteractionModelEngine* imEngine = chip::app::InteractionModelEngine::GetInstance();
        if (!imEngine) {
            _LOG_ERROR("Subscribe: InteractionModelEngine not available");
            MatterError::SetResult(matterPayload, MatterErrorCode::kEngineNotAvailable);
            return false;
        }

        chip::FabricIndex fabricIndex = mCommissioner.GetFabricIndex();
        chip::ScopedNodeId peerId(nodeId, fabricIndex);

        size_t numAttr = attributeIds.size();
        size_t numEv = eventIds.size();
        if (numAttr == 0 && numEv == 0) {
            _LOG_ERROR("Subscribe: at least one attribute or event required");
            MatterError::SetResult(matterPayload, MatterErrorCode::kInvalidParams);
            return false;
        }

        chip::app::AttributePathParams* attrPaths = nullptr;
        if (numAttr > 0) {
            attrPaths = static_cast<chip::app::AttributePathParams*>(
                chip::Platform::MemoryAlloc(numAttr * sizeof(chip::app::AttributePathParams)));
            if (!attrPaths) {
                MatterError::SetResult(matterPayload, MatterErrorCode::kOutOfMemory);
                return false;
            }
            for (size_t i = 0; i < numAttr; i++) {
                attrPaths[i].mEndpointId = endpointId;
                attrPaths[i].mClusterId = clusterId;
                attrPaths[i].mAttributeId = static_cast<chip::AttributeId>(attributeIds[i]);
            }
        }

        chip::app::EventPathParams* evPaths = nullptr;
        if (numEv > 0) {
            evPaths = static_cast<chip::app::EventPathParams*>(
                chip::Platform::MemoryAlloc(numEv * sizeof(chip::app::EventPathParams)));
            if (!evPaths) {
                if (attrPaths)
                    chip::Platform::MemoryFree(attrPaths);
                MatterError::SetResult(matterPayload, MatterErrorCode::kOutOfMemory);
                return false;
            }
            for (size_t i = 0; i < numEv; i++) {
                evPaths[i].mEndpointId = endpointId;
                evPaths[i].mClusterId = clusterId;
                evPaths[i].mEventId = static_cast<chip::EventId>(eventIds[i]);
            }
        }

        MatterSubscribe sub(&mCommissioner, nodeId, endpointId, clusterId,
                             imEngine, minInterval, maxInterval, peerId,
                             attrPaths, numAttr, evPaths, numEv);
        if (!sub.HasCallback()) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kOutOfMemory);
            return false;
        }

        sub.Run();

        if (!sub.WaitForCompletion()) {
            if (sub.ErrorCode() != 0)
                MatterError::SetResult(matterPayload, sub.ErrorCode());
            else
                MatterError::SetResult(matterPayload, MatterErrorCode::kSubscribeTimeout);
            return false;
        }

        AddSubscribeCallback(nodeId, endpointId, clusterId, sub);
        MatterError::SetResult(matterPayload, MatterErrorCode::kSuccess);
        return true;
    }

    // Custom KVS keys for bootstrap credential storage.
    // These are OUR keys — separate from the CHIP SDK's cert store keys.
    // SetupCommissioner manages the cert store; we just cache raw certs here.
    static constexpr const char * kIpkStorageKey  = "agw/matter/ipk";
    static constexpr const char * kRcacStorageKey = "agw/matter/rcac";
    static constexpr const char * kIcacStorageKey = "agw/matter/icac";
    static constexpr const char * kNocStorageKey  = "agw/matter/noc";
    static constexpr chip::FabricIndex kFabricIndex = 1;

    std::atomic<bool> mInitialized;
    std::atomic<bool> mRunning;
    chip::NodeId mCommissioningNodeId;
    std::atomic<bool> mCommissioningInProgress;
    chip::Controller::DeviceCommissioner mCommissioner;
    chip::Controller::AutoCommissioner mAutoCommissioner;
    chip::Controller::ExampleOperationalCredentialsIssuer mOpCredsIssuer;

    chip::KvsPersistentStorageDelegate mStorage;
    chip::Crypto::DefaultSessionKeystore mSessionKeystore;
    chip::Credentials::PersistentStorageOpCertStore mOpCertStore;
    chip::PersistentStorageOperationalKeystore mOpKeystore;
    chip::Credentials::GroupDataProviderImpl mGroupDataProvider;
    chip::DeviceLayer::TestOnlyCommissionableDataProvider mCommissionableDataProvider;
    std::unique_ptr<chip::Credentials::DeviceAttestationVerifier> mTestVerifier;

    std::mutex mSubscribeCallbacksMutex;
    std::map<SubscribeKey, MatterSubscribeCallback::Ptr> mSubscribeCallbacks;

};

// --- MatterController (public facade) ---

MatterController::MatterController() : mImpl(std::make_unique<MatterControllerImpl>()) {}
MatterController::~MatterController() = default;

bool MatterController::Init(log_levels_t level) { return mImpl->Init(level); }
bool MatterController::IsBootstrapRequired() { return mImpl->IsBootstrapRequired(); }
bool MatterController::GenerateBootstrapCsr(const char *csr_nonce, char **csr_pem, char **nocsr_elements) {
    return mImpl->GenerateBootstrapCsr(csr_nonce, csr_pem, nocsr_elements);
}
bool MatterController::Bootstrap(const uint8_t *rcac, size_t rcac_len,
                                 const uint8_t *icac, size_t icac_len,
                                 const uint8_t *ipk, size_t ipk_len,
                                 const uint8_t *noc, size_t noc_len) {
    return mImpl->Bootstrap(rcac, rcac_len, icac, icac_len, ipk, ipk_len, noc, noc_len);
}
bool MatterController::Start() { return mImpl->Start(); }
void MatterController::Stop() { mImpl->Stop(); }
void MatterController::SetLogLevel(log_levels_t level) { mImpl->SetLogLevel(level); }
bool MatterController::IsRunning() const { return mImpl->IsRunning(); }

bool MatterController::DeviceCommand(const std::string& action, json_t* matterPayload) {
    return mImpl->DeviceCommand(action, matterPayload);
}
bool MatterController::DeviceRead(const std::string& action, json_t* matterPayload) {
    return mImpl->DeviceRead(action, matterPayload);
}
bool MatterController::DeviceWrite(const std::string& action, json_t* matterPayload) {
    return mImpl->DeviceWrite(action, matterPayload);
}
bool MatterController::DeviceSubscribe(const std::string& action, json_t* matterPayload) {
    return mImpl->DeviceSubscribe(action, matterPayload);
}

bool MatterController::CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid, const char* password)
{
    return mImpl->CommissionDevice(nodeId, payload, ssid, password);
}

bool MatterController::EstablishCaseSessions(const std::vector<uint64_t>& nodeIds, int retryCount)
{
    return mImpl->EstablishCaseSessions(nodeIds, retryCount);
}

bool MatterController::DeviceDelete(uint64_t nodeId)
{
    return mImpl->DeviceDelete(nodeId);
}

