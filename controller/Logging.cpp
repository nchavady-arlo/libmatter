/*
 * libmatter platform logging implementation.
 *
 * CHIP/Matter's TextOnlyLogging path calls chip::Logging::Platform::LogV
 * as the application-provided sink. Without a definition, programs linking
 * against libmatter.so (arlod, arloutil) crash at runtime with:
 *   symbol lookup error: undefined symbol _ZN4chip7Logging8Platform4LogVE...
 *
 * Route CHIP log output to syslog so it shows up alongside the rest of the
 * Arlo system logs.
 */

#include <platform/logging/LogV.h>
#include <lib/support/logging/Constants.h>

#include <cstdio>
#include <syslog.h>

namespace chip {
namespace Logging {
namespace Platform {

void LogV(const char * module, uint8_t category, const char * msg, va_list args)
{
    char buffer[256];
    int n = vsnprintf(buffer, sizeof(buffer), msg, args);
    if (n < 0) {
        return;
    }

    int level;
    switch (category) {
        case kLogCategory_Error:    level = LOG_ERR;     break;
        case kLogCategory_Progress: level = LOG_INFO;    break;
        case kLogCategory_Detail:   level = LOG_DEBUG;   break;
        default:                    level = LOG_INFO;    break;
    }

    syslog(level, "[CHIP:%s] %s", module ? module : "-", buffer);
}

} // namespace Platform
} // namespace Logging
} // namespace chip
