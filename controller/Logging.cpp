#include <cstdio>
#include <cstring>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/logging/LogV.h>
#include <arlogw/logger.h>

#undef LOG_IDENT
#define LOG_IDENT "matter"

static log_levels_t ModuleToLevel(const char * module)
{
    switch (module[0]) {
    case 'D':
        if (module[1] == 'I') return LL_INFO;   // DIS
        if (module[1] == 'L') return LL_DEBUG;  // DL
        if (module[1] == 'C') return LL_DEBUG;  // DC
        break;
    case 'C':
        if (module[1] == 'T') return LL_INFO;   // CTL
        break;
    case 'S':
        if (module[1] == 'C') return LL_DEBUG;  // SC
        break;
    }
    return LL_TRACE;
}

namespace chip {
namespace Logging {
namespace Platform {

void LogV(const char * module, uint8_t category, const char * msg, va_list v)
{
    log_levels_t level = (category == kLogCategory_Error) ? LL_ERROR : ModuleToLevel(module);

    if (level > agw_log_level[LD_MATTER])
        return;

    char buf[256];
    vsnprintf(buf, sizeof(buf), msg, v);
    logger.log(level, LOG_IDENT ":[%s] %s", module, buf);
}

} // namespace Platform
} // namespace Logging
} // namespace chip
