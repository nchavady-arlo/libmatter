/*
 *  @file       MatterJsonUtils.cpp
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

#include "MatterJsonUtils.h"
#include <lib/core/ErrorStr.h>
#include <lib/support/Base64.h>
#include <lib/support/CodeUtils.h>
#include <charconv>
#include <string_view>

namespace MatterJsonUtils {

const char *GetString(json_t *obj, const char *key)
{
    json_t *v = json_object_get(obj, key);
    return json_is_string(v) ? json_string_value(v) : nullptr;
}

bool GetUInt32(json_t *obj, const char *key, uint32_t &out)
{
    json_t *v = json_object_get(obj, key);
    if (!json_is_integer(v))
        return false;
    json_int_t n = json_integer_value(v);
    if (n < 0 || n > UINT32_MAX)
        return false;
    out = static_cast<uint32_t>(n);
    return true;
}

json_t *GetValue(json_t *obj)
{
    return json_object_get(obj, "value");
}

bool ParseInteger(json_t *v, int64_t &out)
{
    if (json_is_integer(v))
    {
        out = static_cast<int64_t>(json_integer_value(v));
        return true;
    }
    if (json_is_string(v))
    {
        const char *s = json_string_value(v);
        if (!s)
            return false;
        std::string_view sv{s};
        int base = 10;
        const char *start = sv.data();
        if (sv.size() >= 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) {
            base = 16;
            start += 2;
        } else if (sv.size() > 1 && sv[0] == '0') {
            base = 8;
            start += 1;
        }
        int64_t val = 0;
        auto [ptr, ec] = std::from_chars(start, sv.data() + sv.size(), val, base);
        if (ec != std::errc{} || ptr != sv.data() + sv.size())
            return false;
        out = val;
        return true;
    }
    return false;
}

CHIP_ERROR EncodeOctetStringFromJson(chip::TLV::TLVWriter &writer, chip::TLV::Tag tag, json_t *v)
{
    if (json_is_string(v))
    {
        const char *s = json_string_value(v);
        if (!s)
            return CHIP_ERROR_INVALID_ARGUMENT;

        std::string_view sv{s};
        constexpr std::string_view kB64Prefix{"base64:"};
        if (sv.size() >= kB64Prefix.size() && sv.substr(0, kB64Prefix.size()) == kB64Prefix)
        {
            sv.remove_prefix(kB64Prefix.size());
            VerifyOrReturnError(sv.size() <= UINT16_MAX, CHIP_ERROR_INVALID_ARGUMENT);
            std::vector<uint8_t> buf((sv.size() * 3) / 4 + 3);
            uint16_t outLen = chip::Base64Decode(sv.data(), static_cast<uint16_t>(sv.size()), buf.data());
            VerifyOrReturnError(outLen != UINT16_MAX, CHIP_ERROR_INVALID_ARGUMENT);
            return writer.Put(tag, chip::ByteSpan(buf.data(), outLen));
        }

        return writer.Put(tag, chip::ByteSpan(reinterpret_cast<const uint8_t *>(s), sv.size()));
    }

    if (json_is_array(v))
    {
        size_t n = json_array_size(v);
        std::vector<uint8_t> buf;
        buf.reserve(n);
        for (size_t i = 0; i < n; i++)
        {
            json_t *e = json_array_get(v, i);
            if (!json_is_integer(e))
                return CHIP_ERROR_INVALID_ARGUMENT;
            json_int_t b = json_integer_value(e);
            if (b < 0 || b > 255)
                return CHIP_ERROR_INVALID_ARGUMENT;
            buf.push_back(static_cast<uint8_t>(b));
        }
        return writer.Put(tag, chip::ByteSpan(buf.data(), buf.size()));
    }

    return CHIP_ERROR_INVALID_ARGUMENT;
}

CHIP_ERROR EncodeJsonFieldValue(chip::TLV::TLVWriter &writer, chip::TLV::Tag tag, const char *type, json_t *value);

CHIP_ERROR EncodeJsonFieldObject(chip::TLV::TLVWriter &writer, json_t *fieldObj, bool isArrayElement)
{
    if (!json_is_object(fieldObj))
        return CHIP_ERROR_INVALID_ARGUMENT;

    uint32_t id = 0;
    if (!isArrayElement)
    {
        VerifyOrReturnError(GetUInt32(fieldObj, "id", id), CHIP_ERROR_INVALID_ARGUMENT);
    }

    const char *type = GetString(fieldObj, "datatype");
    VerifyOrReturnError(type != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    chip::TLV::Tag tagToUse = isArrayElement ? chip::TLV::AnonymousTag() : chip::TLV::ContextTag(id);
    return EncodeJsonFieldValue(writer, tagToUse, type, GetValue(fieldObj));
}

CHIP_ERROR EncodeJsonFieldArray(chip::TLV::TLVWriter &writer, chip::TLV::Tag tag, const char *elemType, json_t *value)
{
    VerifyOrReturnError(json_is_array(value), CHIP_ERROR_INVALID_ARGUMENT);

    chip::TLV::TLVType container;
    ReturnErrorOnFailure(writer.StartContainer(tag, chip::TLV::kTLVType_Array, container));

    size_t n = json_array_size(value);
    for (size_t i = 0; i < n; i++)
    {
        json_t *e = json_array_get(value, i);
        if (std::string_view{elemType} == "struct")
        {
            VerifyOrReturnError(json_is_array(e), CHIP_ERROR_INVALID_ARGUMENT);
            chip::TLV::TLVType st;
            ReturnErrorOnFailure(writer.StartContainer(chip::TLV::AnonymousTag(), chip::TLV::kTLVType_Structure, st));
            size_t fn = json_array_size(e);
            for (size_t fi = 0; fi < fn; fi++)
            {
                ReturnErrorOnFailure(EncodeJsonFieldObject(writer, json_array_get(e, fi), false));
            }
            ReturnErrorOnFailure(writer.EndContainer(st));
            continue;
        }

        json_auto_t *pseudo = json_object();
        VerifyOrReturnError(pseudo != nullptr, CHIP_ERROR_NO_MEMORY);
        json_object_set_new(pseudo, "datatype", json_string(elemType));
        json_object_set(pseudo, "value", e);
        CHIP_ERROR err = EncodeJsonFieldObject(writer, pseudo, true);
        ReturnErrorOnFailure(err);
    }

    return writer.EndContainer(container);
}

CHIP_ERROR EncodeJsonFieldValue(chip::TLV::TLVWriter &writer, chip::TLV::Tag tag, const char *type, json_t *value)
{
    std::string_view t{type};

    if (t == "null")
        return writer.PutNull(tag);

    if (t == "bool")
    {
        VerifyOrReturnError(json_is_boolean(value), CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, json_is_true(value));
    }

    if (t == "string" || t == "char_string")
    {
        VerifyOrReturnError(json_is_string(value), CHIP_ERROR_INVALID_ARGUMENT);
        const char *s = json_string_value(value);
        VerifyOrReturnError(s != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.PutString(tag, s);
    }

    if (t == "octstr" || t == "octet_string")
        return EncodeOctetStringFromJson(writer, tag, value);

    if (t == "struct")
    {
        VerifyOrReturnError(json_is_array(value), CHIP_ERROR_INVALID_ARGUMENT);
        chip::TLV::TLVType container;
        ReturnErrorOnFailure(writer.StartContainer(tag, chip::TLV::kTLVType_Structure, container));
        size_t n = json_array_size(value);
        for (size_t i = 0; i < n; i++)
        {
            ReturnErrorOnFailure(EncodeJsonFieldObject(writer, json_array_get(value, i), false));
        }
        return writer.EndContainer(container);
    }

    if (t == "array" || t == "list")
        return CHIP_ERROR_INVALID_ARGUMENT;

    if (t == "single" || t == "float")
    {
        float f = 0;
        if (json_is_real(value))
            f = (float)json_real_value(value);
        else if (json_is_integer(value))
            f = (float)json_integer_value(value);
        else
            return CHIP_ERROR_INVALID_ARGUMENT;
        return writer.Put(tag, f);
    }

    if (t == "double")
    {
        double d = 0;
        if (json_is_real(value))
            d = json_real_value(value);
        else if (json_is_integer(value))
            d = (double)json_integer_value(value);
        else
            return CHIP_ERROR_INVALID_ARGUMENT;
        return writer.Put(tag, d);
    }

    int64_t n = 0;
    VerifyOrReturnError(ParseInteger(value, n), CHIP_ERROR_INVALID_ARGUMENT);

    if (t == "uint8" || t == "enum8" || t == "map8" || t == "bitmap8")
    {
        VerifyOrReturnError(n >= 0 && n <= UINT8_MAX, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<uint8_t>(n), true);
    }
    if (t == "uint16" || t == "enum16" || t == "map16" || t == "bitmap16")
    {
        VerifyOrReturnError(n >= 0 && n <= UINT16_MAX, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<uint16_t>(n), true);
    }
    if (t == "uint32" || t == "map32" || t == "bitmap32")
    {
        VerifyOrReturnError(n >= 0, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<uint32_t>(n), true);
    }
    if (t == "uint64" || t == "map64" || t == "bitmap64")
    {
        VerifyOrReturnError(n >= 0, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<uint64_t>(n), true);
    }

    if (t == "int8")
    {
        VerifyOrReturnError(n >= INT8_MIN && n <= INT8_MAX, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<int8_t>(n), true);
    }
    if (t == "int16")
    {
        VerifyOrReturnError(n >= INT16_MIN && n <= INT16_MAX, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<int16_t>(n), true);
    }
    if (t == "int32")
    {
        VerifyOrReturnError(n >= INT32_MIN && n <= INT32_MAX, CHIP_ERROR_INVALID_ARGUMENT);
        return writer.Put(tag, static_cast<int32_t>(n), true);
    }
    if (t == "int64")
        return writer.Put(tag, static_cast<int64_t>(n), true);

    return CHIP_ERROR_INVALID_ARGUMENT;
}

CHIP_ERROR EncodeCommandDataFieldsToTlv(json_t *commandData, std::vector<uint8_t> &out)
{
    if (!commandData || json_is_null(commandData))
    {
        out.clear();
        return CHIP_NO_ERROR;
    }

    VerifyOrReturnError(json_is_array(commandData), CHIP_ERROR_INVALID_ARGUMENT);

    size_t cap = 512;
    for (int attempt = 0; attempt < 7; attempt++)
    {
        out.assign(cap, 0);
        chip::TLV::TLVWriter w;
        w.Init(out.data(), static_cast<uint32_t>(out.size()));

        chip::TLV::TLVType outerStruct;
        CHIP_ERROR err = w.StartContainer(chip::TLV::AnonymousTag(), chip::TLV::kTLVType_Structure, outerStruct);
        if (err != CHIP_NO_ERROR)
        {
            if (err == CHIP_ERROR_NO_MEMORY || err == CHIP_ERROR_BUFFER_TOO_SMALL)
            {
                cap *= 2;
                continue;
            }
            return err;
        }

        size_t n = json_array_size(commandData);
        for (size_t i = 0; i < n && err == CHIP_NO_ERROR; i++)
        {
            json_t *fieldObj = json_array_get(commandData, i);
            if (!json_is_object(fieldObj))
            {
                err = CHIP_ERROR_INVALID_ARGUMENT;
                break;
            }

            const char *type = GetString(fieldObj, "datatype");
            if (type == nullptr)
            {
                err = CHIP_ERROR_INVALID_ARGUMENT;
                break;
            }

            if (std::string_view{type} == "array")
            {
                uint32_t id = 0;
                if (!GetUInt32(fieldObj, "id", id))
                {
                    err = CHIP_ERROR_INVALID_ARGUMENT;
                    break;
                }
                const char *elemType = GetString(fieldObj, "elementType");
                if (elemType == nullptr)
                {
                    err = CHIP_ERROR_INVALID_ARGUMENT;
                    break;
                }
                err = EncodeJsonFieldArray(w, chip::TLV::ContextTag(id), elemType, GetValue(fieldObj));
            }
            else
            {
                err = EncodeJsonFieldObject(w, fieldObj, false);
            }
        }

        if (err == CHIP_NO_ERROR)
            err = w.EndContainer(outerStruct);

        if (err == CHIP_NO_ERROR)
            err = w.Finalize();

        if (err == CHIP_ERROR_NO_MEMORY || err == CHIP_ERROR_BUFFER_TOO_SMALL)
        {
            cap *= 2;
            continue;
        }
        ReturnErrorOnFailure(err);

        uint32_t used = w.GetLengthWritten();
        out.resize(used);
        return CHIP_NO_ERROR;
    }

    return CHIP_ERROR_NO_MEMORY;
}

CHIP_ERROR CopyTlvFieldsIntoWriter(chip::TLV::TLVWriter &dst, const std::vector<uint8_t> &src)
{
    if (src.empty())
        return CHIP_NO_ERROR;

    chip::TLV::TLVReader r;
    r.Init(src.data(), static_cast<uint32_t>(src.size()));

    CHIP_ERROR err = r.Next();
    ReturnErrorOnFailure(err);
    VerifyOrReturnError(r.GetType() == chip::TLV::kTLVType_Structure, CHIP_ERROR_INVALID_TLV_ELEMENT);

    chip::TLV::TLVType container;
    ReturnErrorOnFailure(r.EnterContainer(container));
    while ((err = r.Next()) == CHIP_NO_ERROR)
    {
        ReturnErrorOnFailure(dst.CopyElement(r));
    }
    if (err != CHIP_END_OF_TLV)
        return err;
    ReturnErrorOnFailure(r.ExitContainer(container));
    return CHIP_NO_ERROR;
}

json_t *TlvToJson(chip::TLV::TLVReader *reader)
{
    if (!reader)
        return nullptr;

    switch (reader->GetType()) {
    case chip::TLV::kTLVType_Boolean: {
        bool val = false;
        if (reader->Get(val) == CHIP_NO_ERROR)
            return json_boolean(val);
        break;
    }
    case chip::TLV::kTLVType_UnsignedInteger: {
        uint64_t val = 0;
        if (reader->Get(val) == CHIP_NO_ERROR)
            return json_integer(static_cast<json_int_t>(val));
        break;
    }
    case chip::TLV::kTLVType_SignedInteger: {
        int64_t val = 0;
        if (reader->Get(val) == CHIP_NO_ERROR)
            return json_integer(static_cast<json_int_t>(val));
        break;
    }
    case chip::TLV::kTLVType_UTF8String: {
        chip::CharSpan val;
        if (reader->Get(val) == CHIP_NO_ERROR)
            return json_stringn(val.data(), val.size());
        break;
    }
    case chip::TLV::kTLVType_ByteString: {
        chip::ByteSpan val;
        if (reader->Get(val) == CHIP_NO_ERROR) {
            size_t b64Len = BASE64_ENCODED_LEN(val.size());
            std::vector<char> buf(b64Len + 1);
            uint16_t encoded = chip::Base64Encode(val.data(), static_cast<uint16_t>(val.size()), buf.data());
            buf[encoded] = '\0';
            return json_string(buf.data());
        }
        break;
    }
    case chip::TLV::kTLVType_Array: {
        json_t *arr = json_array();
        chip::TLV::TLVType container;
        if (reader->EnterContainer(container) != CHIP_NO_ERROR) {
            json_decref(arr);
            break;
        }
        while (reader->Next() == CHIP_NO_ERROR) {
            json_t *elem = TlvToJson(reader);
            json_array_append_new(arr, elem ? elem : json_null());
        }
        reader->ExitContainer(container);
        return arr;
    }
    case chip::TLV::kTLVType_Structure: {
        json_t *obj = json_object();
        chip::TLV::TLVType container;
        if (reader->EnterContainer(container) != CHIP_NO_ERROR) {
            json_decref(obj);
            break;
        }
        while (reader->Next() == CHIP_NO_ERROR) {
            chip::TLV::Tag tag = reader->GetTag();
            if (chip::TLV::IsContextTag(tag)) {
                char key[16];
                snprintf(key, sizeof(key), "%u", static_cast<unsigned>(chip::TLV::TagNumFromTag(tag)));
                json_t *val = TlvToJson(reader);
                json_object_set_new(obj, key, val ? val : json_null());
            }
        }
        reader->ExitContainer(container);
        return obj;
    }
    case chip::TLV::kTLVType_Null:
        return json_null();
    default:
        break;
    }
    return nullptr;
}

const char *TlvDataType(chip::TLV::TLVReader *reader)
{
    if (!reader)
        return "unknown";

    switch (reader->GetType()) {
    case chip::TLV::kTLVType_Boolean:
        return "bool";
    case chip::TLV::kTLVType_UnsignedInteger: {
        uint64_t val = 0;
        if (reader->Get(val) == CHIP_NO_ERROR) {
            if (val <= UINT8_MAX) return "uint8";
            if (val <= UINT16_MAX) return "uint16";
            if (val <= UINT32_MAX) return "uint32";
        }
        return "uint64";
    }
    case chip::TLV::kTLVType_SignedInteger: {
        int64_t val = 0;
        if (reader->Get(val) == CHIP_NO_ERROR) {
            if (val >= INT8_MIN && val <= INT8_MAX) return "int8";
            if (val >= INT16_MIN && val <= INT16_MAX) return "int16";
            if (val >= INT32_MIN && val <= INT32_MAX) return "int32";
        }
        return "int64";
    }
    case chip::TLV::kTLVType_UTF8String:
        return "string";
    case chip::TLV::kTLVType_ByteString:
        return "octstr";
    case chip::TLV::kTLVType_Null:
        return "null";
    case chip::TLV::kTLVType_Structure:
        return "struct";
    case chip::TLV::kTLVType_Array:
        return "array";
    default:
        return "unknown";
    }
}

static json_t *BuildReportEntry(uint32_t id, chip::TLV::TLVReader *apData, int status)
{
    json_t *entry = json_object();
    json_object_set_new(entry, "id", json_integer(id));

    if (status == 0 && apData) {
        json_object_set_new(entry, "datatype", json_string(TlvDataType(apData)));
        json_t *val = TlvToJson(apData);
        json_object_set_new(entry, "value", val ? val : json_null());
    }

    json_object_set_new(entry, "result", json_integer(status));
    return entry;
}

json_t *BuildAttributeEntry(uint32_t attributeId, chip::TLV::TLVReader *apData, int status)
{
    return BuildReportEntry(attributeId, apData, status);
}

json_t *BuildEventEntry(uint32_t eventId, chip::TLV::TLVReader *apData, int status)
{
    return BuildReportEntry(eventId, apData, status);
}

} // namespace MatterJsonUtils
