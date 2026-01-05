#pragma once

// Error codes
#define UDC2_SUCCESS                 0
#define UDC2_ERROR_INVALID_PARAM    -1
#define UDC2_ERROR_MEMORY_ALLOC     -2
#define UDC2_ERROR_NETWORK          -3
#define UDC2_ERROR_TIMEOUT          -4
#define UDC2_ERROR_PROTOCOL         -5
#define UDC2_ERROR_FRAGMENTATION    -6

// Config constants
#define MAX_FRAME_SIZE              (1024 * 1024)  // 1MB max limit

// Global state struct
// Global state updated for Slack
typedef struct {
    BOOL    initialized;
    UINT32  beaconId;
    const char* botToken;
    const char* clientchannelId;
    const char* serverchannelId;
} UDC2_STATE;

static UDC2_STATE gUdc2State;