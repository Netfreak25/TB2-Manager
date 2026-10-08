/* MPSSE-only FTDI state used by the TB2 read bridge. UART and generic
 * bit-bang modes are intentionally not initialized. */
#include "ftdi.h"
#include "ftdi_bitbang.h"

#include <furi.h>
#include <stdlib.h>
#include <string.h>

#define TAG                   "TB2_FTDI"
#define FTDI_TX_RX_BUF_SIZE   4096U
#define FTDI_INTERFACE_A      0x01U
#define FTDI_DRIVER_INTERFACE 0x00U

struct Ftdi {
    FtdiModemStatus status;
    FuriStreamBuffer* stream_rx;
    FuriStreamBuffer* stream_tx;
    FtdiBitMode bit_mode;
    uint8_t bit_mode_mask;
    uint8_t latency;
    FtdiBitbang* bitbang;
    FtdiCallbackTxImmediate callback_tx_immediate;
    void* context_tx_immediate;
};

static bool ftdi_check_interface(uint16_t index) {
    uint8_t interface = index & 0xFFU;
    return interface == FTDI_INTERFACE_A || interface == FTDI_DRIVER_INTERFACE;
}

static void ftdi_immediate(void* context) {
    Ftdi* ftdi = context;
    if(ftdi && ftdi->callback_tx_immediate)
        ftdi->callback_tx_immediate(ftdi->context_tx_immediate);
}

Ftdi* ftdi_alloc(uint32_t default_hz) {
    Ftdi* ftdi = calloc(1, sizeof(*ftdi));
    if(!ftdi) return NULL;
    ftdi->latency = 16U;
    ftdi->status.RESERVED1 = 1;
    ftdi->status.TEMT = 1;
    ftdi->status.THRE = 1;
    ftdi->stream_rx = furi_stream_buffer_alloc(FTDI_TX_RX_BUF_SIZE, 1);
    ftdi->stream_tx = furi_stream_buffer_alloc(FTDI_TX_RX_BUF_SIZE, 1);
    if(!ftdi->stream_rx || !ftdi->stream_tx) {
        if(ftdi->stream_tx) furi_stream_buffer_free(ftdi->stream_tx);
        if(ftdi->stream_rx) furi_stream_buffer_free(ftdi->stream_rx);
        free(ftdi);
        return NULL;
    }
    ftdi->bitbang = ftdi_bitbang_alloc(ftdi, default_hz);
    if(!ftdi->bitbang) {
        furi_stream_buffer_free(ftdi->stream_tx);
        furi_stream_buffer_free(ftdi->stream_rx);
        free(ftdi);
        return NULL;
    }
    return ftdi;
}

void ftdi_free(Ftdi* ftdi) {
    if(!ftdi) return;
    ftdi_bitbang_free(ftdi->bitbang);
    furi_stream_buffer_free(ftdi->stream_tx);
    furi_stream_buffer_free(ftdi->stream_rx);
    free(ftdi);
}

void ftdi_set_callback_tx_immediate(Ftdi* ftdi, FtdiCallbackTxImmediate callback, void* context) {
    if(!ftdi) return;
    ftdi->callback_tx_immediate = callback;
    ftdi->context_tx_immediate = context;
}

void ftdi_reset_purge_rx(Ftdi* ftdi) {
    if(!ftdi) return;
    ftdi_bitbang_lock(ftdi->bitbang);
    if(furi_stream_buffer_reset(ftdi->stream_rx) != FuriStatusOk)
        FURI_LOG_E(TAG, "RX purge failed");
    ftdi_bitbang_unlock(ftdi->bitbang);
}

void ftdi_reset_purge_tx(Ftdi* ftdi) {
    if(!ftdi) return;
    ftdi_bitbang_lock(ftdi->bitbang);
    if(furi_stream_buffer_reset(ftdi->stream_tx) != FuriStatusOk)
        FURI_LOG_E(TAG, "TX purge failed");
    ftdi_bitbang_unlock(ftdi->bitbang);
}

void ftdi_reset_sio(Ftdi* ftdi) {
    if(!ftdi) return;
    ftdi_bitbang_lock(ftdi->bitbang);
    ftdi_mpsse_session_reset(ftdi_bitbang_get_mpsse_handle(ftdi->bitbang));
    if(furi_stream_buffer_reset(ftdi->stream_rx) != FuriStatusOk)
        FURI_LOG_E(TAG, "RX reset failed");
    if(furi_stream_buffer_reset(ftdi->stream_tx) != FuriStatusOk)
        FURI_LOG_E(TAG, "TX reset failed");
    ftdi_bitbang_unlock(ftdi->bitbang);
}

uint32_t ftdi_set_tx_buf(Ftdi* ftdi, const uint8_t* data, uint32_t size) {
    if(!ftdi || (!data && size)) return 0;
    uint32_t available = furi_stream_buffer_spaces_available(ftdi->stream_tx);
    if(size > available) {
        FURI_LOG_E(TAG, "FTDI TX buffer overflow");
        size = available;
    }
    return size ? furi_stream_buffer_send(ftdi->stream_tx, data, size, 0) : 0;
}

uint32_t ftdi_get_tx_buf(Ftdi* ftdi, uint8_t* data, uint32_t size) {
    return ftdi && data && size ? furi_stream_buffer_receive(ftdi->stream_tx, data, size, 0) : 0;
}

uint32_t ftdi_available_tx_buf(Ftdi* ftdi) {
    return ftdi ? furi_stream_buffer_bytes_available(ftdi->stream_tx) : 0;
}

uint32_t ftdi_set_rx_buf(Ftdi* ftdi, const uint8_t* data, uint32_t size) {
    if(!ftdi || (!data && size)) return 0;
    uint32_t available = furi_stream_buffer_spaces_available(ftdi->stream_rx);
    if(size > available) {
        FURI_LOG_E(TAG, "FTDI RX buffer overflow");
        size = available;
    }
    return size ? furi_stream_buffer_send(ftdi->stream_rx, data, size, 0) : 0;
}

uint32_t ftdi_get_rx_buf(Ftdi* ftdi, uint8_t* data, uint32_t size, uint32_t timeout) {
    return ftdi && data && size ?
               furi_stream_buffer_receive(ftdi->stream_rx, data, size, timeout) :
               0;
}

uint32_t ftdi_available_rx_buf(Ftdi* ftdi) {
    return ftdi ? furi_stream_buffer_bytes_available(ftdi->stream_rx) : 0;
}

void ftdi_loopback(Ftdi* ftdi) {
    uint8_t data[64];
    uint32_t length = ftdi_get_rx_buf(ftdi, data, sizeof(data), 0);
    if(length) ftdi_set_tx_buf(ftdi, data, length);
}

void ftdi_set_baudrate(Ftdi* ftdi, uint16_t value, uint16_t index) {
    UNUSED(ftdi);
    UNUSED(value);
    UNUSED(index);
}

void ftdi_set_data_config(Ftdi* ftdi, uint16_t value, uint16_t index) {
    UNUSED(ftdi);
    UNUSED(value);
    UNUSED(index);
}

void ftdi_set_flow_ctrl(Ftdi* ftdi, uint16_t index) {
    UNUSED(ftdi);
    UNUSED(index);
}

void ftdi_set_bitmode(Ftdi* ftdi, uint16_t value, uint16_t index) {
    if(!ftdi || !ftdi_check_interface(index)) return;
    ftdi_bitbang_lock(ftdi->bitbang);
    FtdiMpsse* mpsse = ftdi_bitbang_get_mpsse_handle(ftdi->bitbang);
    ftdi_mpsse_session_reset(mpsse);
    memset(&ftdi->bit_mode, 0, sizeof(ftdi->bit_mode));
    ftdi->bit_mode_mask = FTDI_MPSSE_TB2_GPIO_MASK;
    uint8_t requested = (uint8_t)(value >> 8);
    if(requested == 0x02U) ftdi->bit_mode.MPSSE = 1;
    ftdi_bitbang_set_gpio(ftdi->bitbang, ftdi->bit_mode_mask);
    ftdi_bitbang_enable(ftdi->bitbang, ftdi->bit_mode);
    ftdi_mpsse_gpio_set_callback(
        mpsse, ftdi->bit_mode.MPSSE ? ftdi_immediate : NULL, ftdi->bit_mode.MPSSE ? ftdi : NULL);
    ftdi_bitbang_unlock(ftdi->bitbang);
}

void ftdi_set_latency_timer(Ftdi* ftdi, uint16_t value, uint16_t index) {
    if(ftdi && ftdi_check_interface(index)) ftdi->latency = value ? (uint8_t)value : 1U;
}

uint8_t ftdi_get_latency_timer(Ftdi* ftdi) {
    return ftdi ? ftdi->latency : 0;
}

void ftdi_reset_latency_timer(Ftdi* ftdi) {
    UNUSED(ftdi);
}

uint16_t* ftdi_get_modem_status_uint16_t(Ftdi* ftdi) {
    return ftdi ? (uint16_t*)&ftdi->status : NULL;
}

FtdiModemStatus ftdi_get_modem_status(Ftdi* ftdi) {
    FtdiModemStatus empty = {0};
    return ftdi ? ftdi->status : empty;
}

void ftdi_set_modem_status(Ftdi* ftdi, FtdiModemStatus status) {
    if(ftdi) ftdi->status = status;
}

void ftdi_start_uart_tx(Ftdi* ftdi) {
    if(!ftdi) return;
    if(ftdi->bit_mode.MPSSE)
        ftdi_bitbang_notify(ftdi->bitbang);
    else
        ftdi_reset_purge_rx(ftdi);
}

uint8_t ftdi_get_bitbang_gpio(Ftdi* ftdi) {
    return ftdi ? ftdi_bitbang_get_gpio(ftdi->bitbang) : 0;
}

bool ftdi_clock_status(Ftdi* ftdi, Tb2SpiClockStatus* status) {
    return ftdi_bitbang_clock_status(ftdi->bitbang, status);
}
