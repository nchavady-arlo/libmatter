/*
 *    Project configuration file for CHIP/Matter.
 */

#ifndef CHIP_PROJECT_CONFIG_H
#define CHIP_PROJECT_CONFIG_H

// Use Linux platform
#define CHIP_DEVICE_LAYER_TARGET_LINUX 1

// Use mbedTLS for crypto
#define CHIP_CONFIG_USE_OPENSSL_ECC 0

// Crypto configuration for mbedTLS
#define CHIP_CONFIG_RNG_ENTROPY_SOURCE 1
#define CHIP_CONFIG_DEV_RANDOM_ENTROPY_SOURCE "/dev/urandom"

// Use POSIX sockets
#define CHIP_SYSTEM_CONFIG_USE_SOCKETS 1

// Storage configuration
#ifndef CHIP_CONFIG_KVS_PATH
#define CHIP_CONFIG_KVS_PATH "/etc/matter/chip_kvs"
#endif

// CASE address resolution timeout (default 45s is too long)
#define CHIP_CONFIG_ADDRESS_RESOLVE_MAX_LOOKUP_TIME_MS 10000

// Network configuration
#define INET_CONFIG_ENABLE_IPV4 1

// Default number of event handlers
#ifndef CHIP_SYSTEM_CONFIG_NUM_TIMERS
#define CHIP_SYSTEM_CONFIG_NUM_TIMERS 16
#endif

// Logging
#define CHIP_ERROR_LOGGING 1
#define CHIP_PROGRESS_LOGGING 1

#undef CHIP_CONFIG_TRANSPORT_TRACE_ENABLED
#undef PW_RPC_ENABLED
#undef CHIP_APP_MAIN_HAS_ETHERNET_DRIVER
#undef ENABLE_CHIP_SHELL
#endif // CHIP_PROJECT_CONFIG_H
