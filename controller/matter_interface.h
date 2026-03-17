#ifndef MATTER_INTERFACE_H
#define MATTER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

void matter_controller_start(uint64_t fabricId, log_levels_t level);
void matter_controller_stop(void);
bool matter_controller_parse_request(const char* action, json_t* matterPayload, json_t* responsePayload);
bool matter_controller_is_running(void);
bool matter_controller_commission_device(uint64_t nodeId, const char* onboardingPayload, const char* ssid, const char* password);
bool matter_controller_establish_case(uint64_t nodeId, int retryCount);
void matter_event_handler(const char *resource, json_t *matterPayload);

#ifdef __cplusplus
}
#endif

#endif // MATTER_INTERFACE_H
