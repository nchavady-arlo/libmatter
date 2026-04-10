/*
 *  @file       MatterController.cpp
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

    MatterControllerImpl() : mInitialized(false), mRunning(false), mTestVerifier(std::make_unique<TestDeviceAttestationVerifier>()) {}
    ~MatterControllerImpl() {}

    bool IsRunning() const { return mRunning; }

    // Run a callable on the CHIP event loop thread and block until it returns.
    // Usage: auto result = RunOnChipThread([](MatterControllerImpl* self) { return true; });
    template <typename Func>
    auto RunOnChipThread(Func&& fn) -> decltype(fn(std::declval<MatterControllerImpl*>())) {
        using ReturnType = decltype(fn(std::declval<MatterControllerImpl*>()));

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
            using CertChainElement = chip::Credentials::OperationalCertificateStore::CertChainElement;

            bool hasRcac = self->mOpCertStore.HasCertificateForFabric(self->kFabricIndex, CertChainElement::kRcac);
            bool hasNoc  = self->mOpCertStore.HasCertificateForFabric(self->kFabricIndex, CertChainElement::kNoc);

            uint16_t ipkSize = 0;
            bool hasIpk = (self->mStorage.SyncGetKeyValue(self->kIpkStorageKey, nullptr, ipkSize) != CHIP_ERROR_PERSISTED_STORAGE_VALUE_NOT_FOUND);

            bool required = !hasRcac || !hasNoc || !hasIpk;
            if (required)
                _LOG_INFO("Bootstrap required — RCAC=%s NOC=%s IPK=%s",
                          hasRcac ? "ok" : "missing", hasNoc ? "ok" : "missing", hasIpk ? "ok" : "missing");

            return required;
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

        chip::ByteSpan rcacSpan(rcac, rcac_len);
        chip::ByteSpan icacSpan(icac, icac_len);
        chip::ByteSpan ipkSpan(ipk, ipk_len);
        chip::ByteSpan nocSpan(noc, noc_len);

        return RunOnChipThread([rcacSpan, icacSpan, ipkSpan, nocSpan](MatterControllerImpl* self) -> bool {
            // Revert any pending state from a prior failed attempt
            self->mOpCertStore.RevertPendingOpCerts();

            // Store RCAC
            CHIP_ERROR err = self->mOpCertStore.AddNewTrustedRootCertForFabric(self->kFabricIndex, rcacSpan);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Bootstrap: failed to store RCAC: %s", chip::ErrorStr(err));
                return false;
            }

            // Store NOC + ICAC
            err = self->mOpCertStore.AddNewOpCertsForFabric(self->kFabricIndex, nocSpan, icacSpan);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Bootstrap: failed to store NOC/ICAC: %s", chip::ErrorStr(err));
                self->mOpCertStore.RevertPendingOpCerts();
                return false;
            }

            // Commit certs to persistent storage
            err = self->mOpCertStore.CommitOpCertsForFabric(self->kFabricIndex);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Bootstrap: failed to commit certs: %s", chip::ErrorStr(err));
                self->mOpCertStore.RevertPendingOpCerts();
                return false;
            }

            // Store IPK in raw KVS (needed by Start after SetupCommissioner)
            err = self->mStorage.SyncSetKeyValue(self->kIpkStorageKey, ipkSpan.data(), static_cast<uint16_t>(ipkSpan.size()));
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Bootstrap: failed to store IPK: %s", chip::ErrorStr(err));
                return false;
            }

            _LOG_INFO("Bootstrap: credentials installed — RCAC=%zu, ICAC=%zu, NOC=%zu, IPK=%zu",
                      rcacSpan.size(), icacSpan.size(), nocSpan.size(), ipkSpan.size());
            return true;
        });
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
            using CertChainElement = chip::Credentials::OperationalCertificateStore::CertChainElement;

            // Init DeviceControllerFactory
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

            // Load credentials from KVS (stored by Bootstrap)
            uint8_t rcacBuf[chip::Controller::kMaxCHIPDERCertLength];
            chip::MutableByteSpan rcacSpan(rcacBuf);
            if (self->mOpCertStore.GetCertificate(self->kFabricIndex, CertChainElement::kRcac, rcacSpan) != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to load RCAC from KVS — bootstrap required");
                return false;
            }

            uint8_t icacBuf[chip::Controller::kMaxCHIPDERCertLength];
            chip::MutableByteSpan icacSpan(icacBuf);
            if (self->mOpCertStore.GetCertificate(self->kFabricIndex, CertChainElement::kIcac, icacSpan) != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to load ICAC from KVS — bootstrap required");
                return false;
            }

            uint8_t nocBuf[chip::Controller::kMaxCHIPDERCertLength];
            chip::MutableByteSpan nocSpan(nocBuf);
            if (self->mOpCertStore.GetCertificate(self->kFabricIndex, CertChainElement::kNoc, nocSpan) != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to load NOC from KVS — bootstrap required");
                return false;
            }

            // Extract and validate fabricId from RCAC
            chip::FabricId fabricId = chip::kUndefinedFabricId;
            CHIP_ERROR extractErr = chip::Credentials::ExtractFabricIdFromCert(rcacSpan, &fabricId);
            if (extractErr != CHIP_NO_ERROR || fabricId == chip::kUndefinedFabricId) {
                _LOG_ERROR("Failed to extract fabricId from RCAC: %s", chip::ErrorStr(extractErr));
                return false;
            }

            _LOG_INFO("Loaded credentials from KVS: RCAC=%zu, ICAC=%zu, NOC=%zu, fabricId=%llu",
                      rcacSpan.size(), icacSpan.size(), nocSpan.size(), (unsigned long long)fabricId);

            // Setup commissioner with loaded credentials
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
            setupParams.controllerRCAC = rcacSpan;
            setupParams.controllerICAC = icacSpan;
            setupParams.controllerNOC = nocSpan;
            setupParams.enableServerInteractions = true;
            setupParams.controllerVendorId = chip::VendorId::TestVendor1;
            setupParams.deviceAttestationVerifier = self->mTestVerifier.get();
            setupParams.defaultCommissioner = &self->mAutoCommissioner;

            CHIP_ERROR err = chip::Controller::DeviceControllerFactory::GetInstance().SetupCommissioner(setupParams, self->mCommissioner);
            if (err != CHIP_NO_ERROR) {
                _LOG_ERROR("Failed to setup commissioner: %s", chip::ErrorStr(err));
                return false;
            }

            _LOG_INFO("Commissioner initialized with fabricId=%llu", (unsigned long long)fabricId);

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

    bool CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid, const char* password) {
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
        if (error != CHIP_NO_ERROR)
            _LOG_ERROR("Pairing Failed: %s", chip::ErrorStr(error));
        else
            _LOG_INFO("Pairing Complete");
    }

    void OnCommissioningStatusUpdate(chip::PeerId peerId, chip::Controller::CommissioningStage stageCompleted, CHIP_ERROR error) override {
        _LOG_INFO("Commissioning stage '%s' completed: %s", chip::Controller::StageToString(stageCompleted), chip::ErrorStr(error));
    }

    void OnCommissioningFailure(chip::PeerId peerId, CHIP_ERROR error, chip::Controller::CommissioningStage stageFailed,
                                chip::Optional<chip::Credentials::AttestationVerificationResult> additionalErrorInfo) override {
        _LOG_ERROR("Commissioning failed at stage '%s': %s", chip::Controller::StageToString(stageFailed), chip::ErrorStr(error));
    }

    void OnCommissioningComplete(chip::NodeId nodeId, CHIP_ERROR error) override {
        if (error != CHIP_NO_ERROR)
            _LOG_ERROR("Commissioning Failed: %s", chip::ErrorStr(error));
        else
            _LOG_INFO("Commissioning Complete for NodeId: %llu", (unsigned long long)nodeId);
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

    static constexpr const char * kIpkStorageKey = "agw/matter/ipk";
    static constexpr chip::FabricIndex kFabricIndex = 1;

    std::atomic<bool> mInitialized;
    std::atomic<bool> mRunning;
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

