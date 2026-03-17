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
#include "matter_interface.h"
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
#include <credentials/PersistentStorageOpCertStore.h>
#include <credentials/GroupDataProviderImpl.h>
#include <crypto/DefaultSessionKeystore.h>
#include <crypto/PersistentStorageOperationalKeystore.h>
#include <platform/KvsPersistentStorageDelegate.h>
#include <platform/TestOnlyCommissionableDataProvider.h>
#include "MinimalDataModelProvider.h"
#include <lib/support/TestGroupData.h>
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

    MatterControllerImpl() : mRunning(false), mFabricId(1), mTestVerifier(std::make_unique<TestDeviceAttestationVerifier>()) {}
    ~MatterControllerImpl() {}

    bool IsRunning() const { return mRunning; }

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

    bool Start(uint64_t fabricId, log_levels_t level) {
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

        mFabricId = fabricId;

        struct StartContext {
            MatterControllerImpl* self;
            std::promise<bool> promise;
        };

        StartContext ctx{this, {}};
        auto future = ctx.promise.get_future();

        chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
            auto* ctx = reinterpret_cast<StartContext*>(arg);
            auto* self = ctx->self;
            bool success = false;

            do {
                chip::DeviceLayer::ConnectivityMgr().SetBLEAdvertisingEnabled(false);
                chip::DeviceLayer::Internal::BLEMgrImpl().ConfigureBle(0, true);

                self->mStorage.Init(&chip::DeviceLayer::PersistedStorage::KeyValueStoreMgr());
                self->mOpKeystore.Init(&self->mStorage);
                self->mOpCertStore.Init(&self->mStorage);

                self->mGroupDataProvider.SetStorageDelegate(&self->mStorage);
                self->mGroupDataProvider.SetSessionKeystore(&self->mSessionKeystore);
                self->mGroupDataProvider.Init();

                chip::Controller::FactoryInitParams factoryParams;
                factoryParams.systemLayer = &chip::DeviceLayer::SystemLayer();
                factoryParams.fabricIndependentStorage = &self->mStorage;
                factoryParams.dataModelProvider = chip::app::MinimalDataModelProviderInstance();
                factoryParams.opCertStore = &self->mOpCertStore;
                factoryParams.sessionKeystore = &self->mSessionKeystore;
                factoryParams.operationalKeystore = &self->mOpKeystore;
                factoryParams.groupDataProvider = &self->mGroupDataProvider;
                factoryParams.bleLayer = chip::DeviceLayer::ConnectivityMgr().GetBleLayer();

                _LOG_INFO("Params: storage=%p, opCertStore=%p, sessionKeystore=%p, opKeystore=%p, groupData=%p, bleLayer=%p",
                    factoryParams.fabricIndependentStorage,
                    factoryParams.opCertStore,
                    factoryParams.sessionKeystore,
                    factoryParams.operationalKeystore,
                    factoryParams.groupDataProvider,
                    factoryParams.bleLayer);

                CHIP_ERROR initErr = chip::Controller::DeviceControllerFactory::GetInstance().Init(factoryParams);
                if (initErr != CHIP_NO_ERROR) {
                    _LOG_ERROR("Failed to init DeviceControllerFactory: %s", chip::ErrorStr(initErr));
                    break;
                }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                if (self->mOpCredsIssuer.Initialize(self->mStorage) != CHIP_NO_ERROR) {
                    _LOG_ERROR("Failed to init OpCredsIssuer");
                    break;
                }
#pragma GCC diagnostic pop

                self->mNocBuffer.Alloc(chip::Controller::kMaxCHIPDERCertLength);
                chip::MutableByteSpan nocSpan(self->mNocBuffer.Get(), chip::Controller::kMaxCHIPDERCertLength);

                self->mIcacBuffer.Alloc(chip::Controller::kMaxCHIPDERCertLength);
                chip::MutableByteSpan icacSpan(self->mIcacBuffer.Get(), chip::Controller::kMaxCHIPDERCertLength);

                self->mRcacBuffer.Alloc(chip::Controller::kMaxCHIPDERCertLength);
                chip::MutableByteSpan rcacSpan(self->mRcacBuffer.Get(), chip::Controller::kMaxCHIPDERCertLength);

                self->mCommissionerKey.Initialize(chip::Crypto::ECPKeyTarget::ECDSA);

                const chip::NodeId kCommissionerNodeId = 0x12345;

                CHIP_ERROR genErr = self->mOpCredsIssuer.GenerateNOCChainAfterValidation(kCommissionerNodeId, self->mFabricId, chip::kUndefinedCATs,
                                                                     self->mCommissionerKey.Pubkey(), rcacSpan, icacSpan, nocSpan);
                if (genErr != CHIP_NO_ERROR) {
                    _LOG_ERROR("Failed to generate NOC chain: %s", chip::ErrorStr(genErr));
                    break;
                }

                _LOG_INFO("Generated NOC Chain: RCAC=%zu bytes, ICAC=%zu bytes, NOC=%zu bytes", rcacSpan.size(), icacSpan.size(), nocSpan.size());

                chip::Controller::SetupParams setupParams;
                setupParams.pairingDelegate = self;
                setupParams.operationalCredentialsDelegate = &self->mOpCredsIssuer;
                setupParams.operationalKeypair = &self->mCommissionerKey;
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
                    break;
                }

                _LOG_INFO("Commissioner initialized");

                chip::ByteSpan ipkSpan = chip::GroupTesting::DefaultIpkValue::GetDefaultIpk();

                uint64_t compressedFabricId = self->mCommissioner.GetCompressedFabricId();
                uint8_t compressedFabricIdBuffer[sizeof(uint64_t)];
                chip::Encoding::BigEndian::Put64(compressedFabricIdBuffer, compressedFabricId);
                chip::ByteSpan compressedFabricIdSpan(compressedFabricIdBuffer);

                CHIP_ERROR ipkErr = chip::Credentials::SetSingleIpkEpochKey(&self->mGroupDataProvider, self->mCommissioner.GetFabricIndex(), ipkSpan, compressedFabricIdSpan);
                if (ipkErr != CHIP_NO_ERROR)
                    _LOG_ERROR("Failed to set IPK: %s", chip::ErrorStr(ipkErr));
                else
                    _LOG_INFO("IPK set successfully for fabric index %d", self->mCommissioner.GetFabricIndex());

                success = true;
            } while (false);

            ctx->promise.set_value(success);
        }, reinterpret_cast<intptr_t>(&ctx));

        if (!future.get()) {
            _LOG_ERROR("Matter controller init failed on CHIP thread.");
            return false;
        }

        mRunning = true;
        _LOG_INFO("Matter controller started.");
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

        _LOG_INFO("Matter controller stopped.");
    }

    bool ParseRequest(const std::string& actionStr, json_t* matterPayload) {
        if (!mRunning) {
            MatterError::SetResult(matterPayload, MatterErrorCode::kCommandFailed);
            return false;
        }

        Action action = ParseAction(actionStr);
        if (action == Action::kUnknown) {
            _LOG_ERROR("Unsupported action: %s", actionStr.c_str());
            MatterError::SetResult(matterPayload, MatterErrorCode::kUnsupportedAction);
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

        switch (action) {
        case Action::kCommand:
            return ParseCommand(nodeId, endpointId, clusterId, matterPayload);
        case Action::kSubscribe:
            return ParseSubscribe(nodeId, endpointId, clusterId, matterPayload);
        case Action::kRead:
        case Action::kWrite:
            _LOG_ERROR("Action '%s' not yet implemented", actionStr.c_str());
            [[fallthrough]];
        default:
            MatterError::SetResult(matterPayload, MatterErrorCode::kUnsupportedAction);
            return false;
        }
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
    static Action ParseAction(const std::string& action) {
        if (action == "command")   return Action::kCommand;
        if (action == "read")      return Action::kRead;
        if (action == "write")     return Action::kWrite;
        if (action == "subscribe") return Action::kSubscribe;
        return Action::kUnknown;
    }

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

    std::atomic<bool> mRunning;
    uint64_t mFabricId;
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

    chip::Crypto::P256Keypair mCommissionerKey;
    chip::Platform::ScopedMemoryBuffer<uint8_t> mNocBuffer;
    chip::Platform::ScopedMemoryBuffer<uint8_t> mIcacBuffer;
    chip::Platform::ScopedMemoryBuffer<uint8_t> mRcacBuffer;

    std::mutex mSubscribeCallbacksMutex;
    std::map<SubscribeKey, MatterSubscribeCallback::Ptr> mSubscribeCallbacks;

};

// --- MatterController (public facade) ---

MatterController::MatterController() : mImpl(std::make_unique<MatterControllerImpl>()) {}
MatterController::~MatterController() = default;

bool MatterController::Start(uint64_t fabricId, log_levels_t level) { return mImpl->Start(fabricId, level); }
void MatterController::Stop() { mImpl->Stop(); }
void MatterController::SetLogLevel(log_levels_t level) { mImpl->SetLogLevel(level); }
bool MatterController::IsRunning() const { return mImpl->IsRunning(); }

bool MatterController::ParseRequest(const std::string& action, json_t* matterPayload)
{
    return mImpl->ParseRequest(action, matterPayload);
}

bool MatterController::CommissionDevice(uint64_t nodeId, const char* payload, const char* ssid, const char* password)
{
    return mImpl->CommissionDevice(nodeId, payload, ssid, password);
}

bool MatterController::EstablishCaseSessions(const std::vector<uint64_t>& nodeIds, int retryCount)
{
    return mImpl->EstablishCaseSessions(nodeIds, retryCount);
}

// --- C API ---

void matter_controller_start(uint64_t fabricId, log_levels_t level)
{
    MatterController::singleton().Start(fabricId, level);
}

void matter_controller_stop()
{
    MatterController::singleton().Stop();
}

bool matter_controller_parse_request(const char* action, json_t* matterPayload, json_t* responsePayload)
{
    bool result = MatterController::singleton().ParseRequest(action, matterPayload);
    if (responsePayload) {
        json_t *outprops = json_object();
        if (outprops) {
            json_object_set_new(outprops, "matterPayload", json_deep_copy(matterPayload));
            json_object_set_new(responsePayload, "properties", outprops);
        }
    }
    return result;
}

bool matter_controller_is_running()
{
    return MatterController::singleton().IsRunning();
}

bool matter_controller_commission_device(uint64_t nodeId, const char* onboardingPayload, const char* ssid, const char* password)
{
    return MatterController::singleton().CommissionDevice(nodeId, onboardingPayload, ssid, password);
}

bool matter_controller_establish_case(uint64_t nodeId, int retryCount)
{
    std::vector<uint64_t> vec(1, nodeId);
    return MatterController::singleton().EstablishCaseSessions(vec, retryCount);
}
