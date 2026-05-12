/*
 *    Project configuration file for CHIP/Matter.
 */

#ifndef CHIP_PROJECT_CONFIG_H
#define CHIP_PROJECT_CONFIG_H

// ABI-critical: controls struct layouts and conditional members in SDK headers
#define CHIP_DEVICE_LAYER_TARGET_LINUX 1
#define CHIP_SYSTEM_CONFIG_USE_SOCKETS 1
#define INET_CONFIG_ENABLE_IPV4 1

#ifndef CHIP_SYSTEM_CONFIG_NUM_TIMERS
#define CHIP_SYSTEM_CONFIG_NUM_TIMERS 16
#endif

// Storage path (used in libmatter code, not just SDK internals)
#ifndef CHIP_CONFIG_KVS_PATH
#define CHIP_CONFIG_KVS_PATH "/etc/matter/chip_kvs"
#endif

// Logging: these control header-inlined ChipLog* macros
#define CHIP_ERROR_LOGGING 1
#define CHIP_PROGRESS_LOGGING 1
#define CHIP_DETAIL_LOGGING 1
#define CHIP_AUTOMATION_LOGGING 1

// Disable unused features
#undef CHIP_CONFIG_TRANSPORT_TRACE_ENABLED
#undef PW_RPC_ENABLED
#undef CHIP_APP_MAIN_HAS_ETHERNET_DRIVER
#undef ENABLE_CHIP_SHELL
#endif // CHIP_PROJECT_CONFIG_H
