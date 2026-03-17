/*
 *  @file       MatterCommand.cpp
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

#include "MatterCommand.h"
#include "MatterJsonUtils.h"
#include "logger.h"
#include <app/CommandSender.h>
#include <platform/CHIPDeviceLayer.h>
#include <lib/core/ErrorStr.h>

// --- GenericCommandSenderCallback ---

class GenericCommandSenderCallback : public chip::app::CommandSender::ExtendableCallback
{
public:
    explicit GenericCommandSenderCallback(MatterCommand::DoneCallback done) : mDone(std::move(done)) {}

    void OnResponse(chip::app::CommandSender * /*commandSender*/,
                    const chip::app::CommandSender::ResponseData & aResponseData) override
    {
        int code = 0;
        if (aResponseData.statusIB.mStatus != chip::Protocols::InteractionModel::Status::Success) {
            code = static_cast<int>(aResponseData.statusIB.mStatus);
            _LOG_ERROR("Matter command failed: status=0x%02x", static_cast<unsigned>(code & 0xFF));
        }
        if (mDone)
            mDone(code == 0, code, code == 0 ? nullptr : "Matter command failed");
    }

    void OnError(const chip::app::CommandSender * /*apCommandSender*/,
                 const chip::app::CommandSender::ErrorData & aErrorData) override
    {
        _LOG_ERROR("Command invoke error: %s", chip::ErrorStr(aErrorData.error));
        if (mDone)
            mDone(false, MatterError::ToInt(aErrorData.error), MatterError::ToMessage(MatterError::ToInt(aErrorData.error)));
    }

    void OnDone(chip::app::CommandSender * apCommandSender) override
    {
        chip::Platform::Delete(apCommandSender);
        chip::Platform::Delete(this);
    }

private:
    MatterCommand::DoneCallback mDone;
};

// --- MatterCommand ---

MatterCommand::MatterCommand(chip::Controller::DeviceCommissioner* comm, chip::NodeId nid,
                              chip::EndpointId eid, chip::ClusterId cid, uint32_t cmd,
                              std::vector<uint8_t> encodedTlv)
    : MatterOperation(comm, nid), mEndpointId(eid), mClusterId(cid), mCommandId(cmd),
      mEncodedTlv(std::move(encodedTlv))
{
}

CHIP_ERROR MatterCommand::InvokeCommand(chip::Messaging::ExchangeManager& exchangeMgr,
                                         const chip::SessionHandle& sessionHandle,
                                         const DoneCallback& done)
{
    const bool hasData = !mEncodedTlv.empty();

    auto* cb = chip::Platform::New<GenericCommandSenderCallback>(done);
    if (!cb)
        return CHIP_ERROR_NO_MEMORY;

    auto* sender = chip::Platform::New<chip::app::CommandSender>(cb, &exchangeMgr, /*isTimedRequest*/ false,
                                                                  /*suppressResponse*/ false, /*allowLargePayload*/ false);
    if (!sender) {
        chip::Platform::Delete(cb);
        return CHIP_ERROR_NO_MEMORY;
    }

    chip::app::CommandPathParams commandPath = { mEndpointId, 0, mClusterId, mCommandId, chip::app::CommandPathFlags::kEndpointIdValid };
    chip::app::CommandSender::PrepareCommandParameters prep;
    prep.SetStartDataStruct(hasData);
    CHIP_ERROR err = sender->PrepareCommand(commandPath, prep);
    if (err != CHIP_NO_ERROR) {
        chip::Platform::Delete(sender);
        chip::Platform::Delete(cb);
        return err;
    }

    if (hasData) {
        chip::TLV::TLVWriter* w = sender->GetCommandDataIBTLVWriter();
        if (!w) {
            chip::Platform::Delete(sender);
            chip::Platform::Delete(cb);
            return CHIP_ERROR_INCORRECT_STATE;
        }

        err = MatterJsonUtils::CopyTlvFieldsIntoWriter(*w, mEncodedTlv);
        if (err != CHIP_NO_ERROR) {
            chip::Platform::Delete(sender);
            chip::Platform::Delete(cb);
            return err;
        }
    }

    chip::app::CommandSender::FinishCommandParameters fin;
    fin.SetEndDataStruct(hasData);
    err = sender->FinishCommand(fin);
    if (err != CHIP_NO_ERROR) {
        chip::Platform::Delete(sender);
        chip::Platform::Delete(cb);
        return err;
    }

    err = sender->SendCommandRequest(sessionHandle);
    if (err != CHIP_NO_ERROR) {
        chip::Platform::Delete(sender);
        chip::Platform::Delete(cb);
        return err;
    }

    return CHIP_NO_ERROR;
}

void MatterCommand::OnDeviceConnected(chip::Messaging::ExchangeManager& exchangeMgr,
                                       const chip::SessionHandle& sessionHandle)
{
    _LOG_INFO("Sending command (endpoint=%u, cluster=0x%04x, command=%u)",
              mEndpointId, mClusterId, mCommandId);

    CHIP_ERROR err = InvokeCommand(exchangeMgr, sessionHandle, [this](bool ok, int code, const char* msg) {
        _LOG_INFO("Command response: %s", ok ? "Success" : "Failure");
        if (!ok && msg)
            SetError(code, msg);
        Complete(ok);
    });

    if (err != CHIP_NO_ERROR) {
        _LOG_ERROR("Failed to invoke command: %s", chip::ErrorStr(err));
        if (err == CHIP_ERROR_INCORRECT_STATE && mAttempts == 0)
        {
            mAttempts++;
            mScheduledErrorCode = MatterError::ToInt(err);
            mScheduledErrorMessage = MatterError::ToMessage(MatterError::ToInt(err));
            _LOG_WARNING("Invoke returned INCORRECT_STATE; releasing CASE session and retrying once (node=%llu)",
                         (unsigned long long)mNodeId);

            chip::DeviceLayer::PlatformMgr().ScheduleWork([](intptr_t arg) {
                auto* self = reinterpret_cast<MatterCommand*>(arg);
                if (self->mCommissioner != nullptr)
                {
                    if (auto* caseMgr = self->mCommissioner->CASESessionMgr())
                    {
                        caseMgr->ReleaseSession(self->mCommissioner->GetPeerScopedId(self->mNodeId));
                    }
                    CHIP_ERROR connErr = self->mCommissioner->GetConnectedDevice(
                        self->mNodeId, &self->ConnectedCallback(), &self->FailureCallback());
                    if (connErr != CHIP_NO_ERROR)
                    {
                        _LOG_ERROR("Retry GetConnectedDevice failed: %s", chip::ErrorStr(connErr));
                        self->SetError(MatterError::ToInt(connErr), MatterError::ToMessage(MatterError::ToInt(connErr)));
                        self->Complete(false);
                    }
                }
                else
                {
                    self->SetError(self->mScheduledErrorCode, self->mScheduledErrorMessage.c_str());
                    self->Complete(false);
                }
            }, reinterpret_cast<intptr_t>(this));
            return;
        }

        SetError(MatterError::ToInt(err), MatterError::ToMessage(MatterError::ToInt(err)));
        Complete(false);
    }
}
