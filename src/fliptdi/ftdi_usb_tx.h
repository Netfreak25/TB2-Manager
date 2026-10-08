#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef uint16_t (*FtdiUsbTxFill)(void* context, uint8_t* packet, uint16_t capacity);
typedef bool (*FtdiUsbTxSubmit)(void* context, const uint8_t* packet, uint16_t length);

typedef enum {
    FtdiUsbTxSubmitted,
    FtdiUsbTxRetry,
    FtdiUsbTxDeferred,
} FtdiUsbTxStep;

typedef struct {
    uint16_t pending_length;
    uint8_t self_retries;
    bool retrying;
} FtdiUsbTxState;

static inline void ftdi_usb_tx_reset(FtdiUsbTxState* state) {
    state->pending_length = 0;
    state->self_retries = 0;
    state->retrying = false;
}

/** Submit one packet without consuming it again after a transient endpoint
 * failure. FtdiUsbTxRetry authorizes one bounded self-retry; Deferred leaves
 * the exact packet pending for a later endpoint or host event. */
static inline FtdiUsbTxStep ftdi_usb_tx_attempt(
    FtdiUsbTxState* state,
    uint8_t* packet,
    uint16_t capacity,
    FtdiUsbTxFill fill,
    void* fill_context,
    FtdiUsbTxSubmit submit,
    void* submit_context,
    uint8_t retry_limit) {
    if(!state || !packet || !capacity || !fill || !submit) return FtdiUsbTxDeferred;
    if(!state->pending_length) {
        state->pending_length = fill(fill_context, packet, capacity);
        if(!state->pending_length || state->pending_length > capacity) {
            ftdi_usb_tx_reset(state);
            return FtdiUsbTxDeferred;
        }
    }
    if(submit(submit_context, packet, state->pending_length)) {
        ftdi_usb_tx_reset(state);
        return FtdiUsbTxSubmitted;
    }
    state->retrying = true;
    if(state->self_retries >= retry_limit) return FtdiUsbTxDeferred;
    state->self_retries++;
    return FtdiUsbTxRetry;
}
