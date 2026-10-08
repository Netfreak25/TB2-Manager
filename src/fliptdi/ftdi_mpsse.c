#include "ftdi_mpsse.h"
#include "furi.h"
#include <furi_hal.h>
#include <string.h>
#include <stdlib.h>
#include "ftdi_gpio.h"
#include "ftdi_mpsse_data.h"
#include "tb2_spi_backend.h"

#define TAG "FTDI_MPSSE"

typedef void (*FtdiMpsseGpioO)(uint8_t state);

#define FTDI_MPSSE_TIMEOUT    5000
#define FTDI_MPSSE_TX_RX_SIZE (4096UL)

/* TB2 native-SPI extension. The host still speaks the existing FlipTDI/MPSSE stream,
 * but verified SPI byte transfers are executed by the Flipper external hardware-SPI bus. */
#define TB2_USE_NATIVE_SPI     (1)
#define TB2_MPSSE_CMD_HW_JEDEC (0xF0)

typedef enum {
    FtdiMpsseErrorNone = 0,
    FtdiMpsseErrorTimeout,
    FtdiMpsseErrorTxOverflow,
} FtdiMpsseError;

struct FtdiMpsse {
    Ftdi* ftdi;
    uint8_t gpio_state;
    uint8_t gpio_mask;
    uint16_t data_size;
    bool is_loopback;
    bool is_div5;
    bool divisor_valid;
    uint16_t divisor;
    bool is_clk3phase;
    bool is_adaptive;
    FtdiMpsseError error;

    FtdiMpsseGpioO gpio_o[8];
    uint8_t gpio_mask_old;

    FtdiMpsseCallbackImmediate callback_immediate;
    void* context_immediate;

    uint8_t* data_buf;
    uint16_t data_buf_count_byte;

    Tb2SpiBackend* tb2_spi;
};

void ftdi_mpsse_gpio_set_callback(
    FtdiMpsse* ftdi_mpsse,
    FtdiMpsseCallbackImmediate callback,
    void* context) {
    ftdi_mpsse->callback_immediate = callback;
    ftdi_mpsse->context_immediate = context;
}

void ftdi_mpsse_gpio_set_direction(FtdiMpsse* ftdi_mpsse) {
    ftdi_gpio_set_direction(ftdi_mpsse->gpio_mask);
    if(ftdi_mpsse->gpio_mask & 0b00000001) {
        ftdi_mpsse->gpio_o[0] = ftdi_gpio_set_b0;
    } else {
        ftdi_mpsse->gpio_o[0] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b00000010) {
        ftdi_mpsse->gpio_o[1] = ftdi_gpio_set_b1;
    } else {
        ftdi_mpsse->gpio_o[1] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b00000100) {
        ftdi_mpsse->gpio_o[2] = ftdi_gpio_set_b2;
    } else {
        ftdi_mpsse->gpio_o[2] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b00001000) {
        ftdi_mpsse->gpio_o[3] = ftdi_gpio_set_b3;
    } else {
        ftdi_mpsse->gpio_o[3] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b00010000) {
        ftdi_mpsse->gpio_o[4] = ftdi_gpio_set_b4;
    } else {
        ftdi_mpsse->gpio_o[4] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b00100000) {
        ftdi_mpsse->gpio_o[5] = ftdi_gpio_set_b5;
    } else {
        ftdi_mpsse->gpio_o[5] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b01000000) {
        ftdi_mpsse->gpio_o[6] = ftdi_gpio_set_b6;
    } else {
        ftdi_mpsse->gpio_o[6] = ftdi_gpio_set_noop;
    }

    if(ftdi_mpsse->gpio_mask & 0b10000000) {
        ftdi_mpsse->gpio_o[7] = ftdi_gpio_set_b7;
    } else {
        ftdi_mpsse->gpio_o[7] = ftdi_gpio_set_noop;
    }
}

void ftdi_mpsse_gpio_init(FtdiMpsse* ftdi_mpsse) {
    ftdi_gpio_init(ftdi_mpsse->gpio_mask);
    ftdi_mpsse_gpio_set_direction(ftdi_mpsse);
}

static inline void ftdi_mpsse_gpio_set(FtdiMpsse* ftdi_mpsse) {
    ftdi_mpsse->gpio_o[0](ftdi_mpsse->gpio_state & 0b00000001);
    ftdi_mpsse->gpio_o[1](ftdi_mpsse->gpio_state & 0b00000010);
    ftdi_mpsse->gpio_o[2](ftdi_mpsse->gpio_state & 0b00000100);
    ftdi_mpsse->gpio_o[3](ftdi_mpsse->gpio_state & 0b00001000);
    ftdi_mpsse->gpio_o[4](ftdi_mpsse->gpio_state & 0b00010000);
    ftdi_mpsse->gpio_o[5](ftdi_mpsse->gpio_state & 0b00100000);
    ftdi_mpsse->gpio_o[6](ftdi_mpsse->gpio_state & 0b01000000);
    ftdi_mpsse->gpio_o[7](ftdi_mpsse->gpio_state & 0b10000000);
}

static inline uint8_t ftdi_mpsse_gpio_get(void) {
    uint8_t gpio_data = 0;
    gpio_data |= ftdi_gpio_get_b0();
    gpio_data |= ftdi_gpio_get_b1();
    gpio_data |= ftdi_gpio_get_b2();
    gpio_data |= ftdi_gpio_get_b3();
    gpio_data |= ftdi_gpio_get_b4();
    gpio_data |= ftdi_gpio_get_b5();
    gpio_data |= ftdi_gpio_get_b6();
    gpio_data |= ftdi_gpio_get_b7();
    return gpio_data;
}

static void ftdi_mpsse_restore_gpio(FtdiMpsse* ftdi_mpsse) {
    /* furi_hal_spi_release() returns ownership to GPIO. Re-apply the current MPSSE
     * direction/value explicitly so repeated native transactions start from a known idle state. */
    ftdi_mpsse_gpio_set_direction(ftdi_mpsse);
    ftdi_mpsse->gpio_mask_old = ftdi_mpsse->gpio_mask;
    ftdi_mpsse_gpio_set(ftdi_mpsse);
}

static void ftdi_mpsse_native_spi_release(FtdiMpsse* ftdi_mpsse) {
#if TB2_USE_NATIVE_SPI
    if(ftdi_mpsse->tb2_spi && tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
        tb2_spi_backend_release(ftdi_mpsse->tb2_spi);
        ftdi_mpsse_restore_gpio(ftdi_mpsse);
    }
#else
    UNUSED(ftdi_mpsse);
#endif
}

void ftdi_mpsse_native_spi_reset(FtdiMpsse* ftdi_mpsse) {
    if(!ftdi_mpsse) return;
#if TB2_USE_NATIVE_SPI
    /* Reset/deinit must never leave the flash selected. */
    ftdi_mpsse->gpio_state |= FTDI_MPSSE_TB2_CS_BIT;
    ftdi_mpsse->gpio_mask = FTDI_MPSSE_TB2_GPIO_MASK;
    if(ftdi_mpsse->tb2_spi && tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
        ftdi_mpsse_native_spi_release(ftdi_mpsse);
    } else {
        ftdi_mpsse_restore_gpio(ftdi_mpsse);
    }
    if(ftdi_mpsse->tb2_spi) tb2_spi_backend_invalidate(ftdi_mpsse->tb2_spi);
#endif
}

static bool ftdi_mpsse_native_spi_selected(FtdiMpsse* ftdi_mpsse) {
#if TB2_USE_NATIVE_SPI
    return ftdi_mpsse->tb2_spi && ftdi_mpsse->gpio_mask == FTDI_MPSSE_TB2_GPIO_MASK &&
           !(ftdi_mpsse->gpio_state & FTDI_MPSSE_TB2_CS_BIT);
#else
    UNUSED(ftdi_mpsse);
    return false;
#endif
}

static bool ftdi_mpsse_native_spi_begin(FtdiMpsse* ftdi_mpsse) {
#if TB2_USE_NATIVE_SPI
    if(!ftdi_mpsse_native_spi_selected(ftdi_mpsse)) return false;
    if(tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) return true;
    if(!tb2_spi_backend_acquire(ftdi_mpsse->tb2_spi)) {
        tb2_spi_backend_invalidate(ftdi_mpsse->tb2_spi);
        FURI_LOG_E(TAG, "TB2 native SPI acquire failed");
        return false;
    }
    return true;
#else
    UNUSED(ftdi_mpsse);
    return false;
#endif
}

static void ftdi_mpsse_native_spi_failure(FtdiMpsse* ftdi_mpsse, const char* stage) {
#if TB2_USE_NATIVE_SPI
    FURI_LOG_E(TAG, "TB2 native SPI %s failed", stage);
    UNUSED(stage);
    /* Fail safe: deselect the flash before returning ownership to GPIO. */
    ftdi_mpsse->gpio_state |= FTDI_MPSSE_TB2_CS_BIT;
    ftdi_mpsse_native_spi_release(ftdi_mpsse);
    if(ftdi_mpsse->tb2_spi) tb2_spi_backend_invalidate(ftdi_mpsse->tb2_spi);
#else
    UNUSED(ftdi_mpsse);
    UNUSED(stage);
#endif
}

void ftdi_mpsse_session_reset(FtdiMpsse* mpsse) {
    ftdi_mpsse_native_spi_reset(mpsse);
    mpsse->is_div5 = true;
    mpsse->divisor_valid = false;
    mpsse->divisor = 0;
    tb2_spi_backend_reset_clock(mpsse->tb2_spi);
}

Tb2SpiClockStatus ftdi_mpsse_clock_status(FtdiMpsse* mpsse) {
    return tb2_spi_backend_clock_status(mpsse->tb2_spi);
}

bool ftdi_mpsse_clock_failed(FtdiMpsse* mpsse) {
    return ftdi_mpsse_clock_status(mpsse).clock_error;
}

static void ftdi_mpsse_update_clock(FtdiMpsse* mpsse) {
    if(!mpsse->divisor_valid) return;
    uint32_t base = mpsse->is_div5 ? 12000000U : 60000000U;
    uint32_t requested = base / (2U * ((uint32_t)mpsse->divisor + 1U));
    if(!tb2_spi_backend_set_clock(mpsse->tb2_spi, requested)) ftdi_mpsse_native_spi_reset(mpsse);
}

FtdiMpsse* ftdi_mpsse_alloc(Ftdi* ftdi, uint32_t default_hz) {
    if(!ftdi) return NULL;
    FtdiMpsse* ftdi_mpsse = calloc(1, sizeof(FtdiMpsse));
    if(!ftdi_mpsse) return NULL;
    ftdi_mpsse->ftdi = ftdi;
    ftdi_mpsse->gpio_state = FTDI_MPSSE_TB2_CS_BIT;
    ftdi_mpsse->gpio_mask = FTDI_MPSSE_TB2_GPIO_MASK;
    ftdi_mpsse->data_size = 0;
    ftdi_mpsse->is_loopback = false;
    ftdi_mpsse->is_div5 = true;
    ftdi_mpsse->is_clk3phase = false;
    ftdi_mpsse->is_adaptive = false;

    ftdi_mpsse->error = FtdiMpsseErrorNone;
    ftdi_mpsse->data_buf = malloc(FTDI_MPSSE_TX_RX_SIZE * sizeof(uint8_t));
    ftdi_mpsse->data_buf_count_byte = 0;
    ftdi_mpsse->gpio_mask_old = 0xFF;
    ftdi_mpsse->tb2_spi = tb2_spi_backend_alloc(default_hz);
    if(!ftdi_mpsse->data_buf || !ftdi_mpsse->tb2_spi) {
        FURI_LOG_E(TAG, "TB2 native SPI allocation failed");
        tb2_spi_backend_free(ftdi_mpsse->tb2_spi);
        free(ftdi_mpsse->data_buf);
        free(ftdi_mpsse);
        return NULL;
    }

    ftdi_mpsse_gpio_init(ftdi_mpsse);
    ftdi_mpsse_gpio_set(ftdi_mpsse);

    return ftdi_mpsse;
}

void ftdi_mpsse_free(FtdiMpsse* ftdi_mpsse) {
    if(!ftdi_mpsse) return;
    ftdi_mpsse_native_spi_reset(ftdi_mpsse);
    tb2_spi_backend_free(ftdi_mpsse->tb2_spi);
    ftdi_mpsse->tb2_spi = NULL;
    free(ftdi_mpsse->data_buf);
    ftdi_gpio_deinit();
    free(ftdi_mpsse);
    ftdi_mpsse = NULL;
}

uint8_t ftdi_mpsse_get_data_stream(FtdiMpsse* ftdi_mpsse) {
    uint8_t data = 0;
    if(ftdi_get_rx_buf(ftdi_mpsse->ftdi, &data, 1, FTDI_MPSSE_TIMEOUT) != 1) {
        FURI_LOG_E(TAG, "Timeout");
        ftdi_mpsse->error = FtdiMpsseErrorTimeout;
    }
#ifdef FTDI_DEBUG
    FURI_LOG_RAW_I("0x%02X ", data);
#endif
    return data;
}

void ftdi_mpssse_set_data_stream(FtdiMpsse* ftdi_mpsse, uint8_t* data, uint16_t size) {
    ftdi_set_tx_buf(ftdi_mpsse->ftdi, data, size);
}

static inline void ftdi_mpsse_skeep_data(FtdiMpsse* ftdi_mpsse) {
    ftdi_mpsse->data_size++;
    while(ftdi_mpsse->data_size--) {
        if(ftdi_mpsse->error != FtdiMpsseErrorNone) return;
        ftdi_mpsse_get_data_stream(ftdi_mpsse);
    }
}

void ftdi_mpsse_get_data(FtdiMpsse* ftdi_mpsse) {
    //todo add support for tx buffer, data_size_max = 0xFF00
    ftdi_mpsse->data_size++;
    if(ftdi_mpsse->data_size > FTDI_MPSSE_TX_RX_SIZE) {
        ftdi_mpsse->error = FtdiMpsseErrorTxOverflow;
        FURI_LOG_E(TAG, "Tx buffer overflow");
        ftdi_mpsse_skeep_data(ftdi_mpsse);
        ftdi_mpsse->data_size = 0;
    }

    uint16_t received = 0;
    while(received < ftdi_mpsse->data_size) {
        uint32_t chunk = ftdi_get_rx_buf(
            ftdi_mpsse->ftdi,
            ftdi_mpsse->data_buf + received,
            ftdi_mpsse->data_size - received,
            FTDI_MPSSE_TIMEOUT);
        if(!chunk) {
            FURI_LOG_E(TAG, "Timeout");
            ftdi_mpsse->error = FtdiMpsseErrorTimeout;
            break;
        }
        received += (uint16_t)chunk;
    }
    ftdi_mpsse->data_buf_count_byte = received;
}

static uint16_t ftdi_mpsse_get_data_size(FtdiMpsse* ftdi_mpsse) {
    return ftdi_mpsse_get_data_stream(ftdi_mpsse) |
           (uint16_t)ftdi_mpsse_get_data_stream(ftdi_mpsse) << 8;
}

static inline void ftdi_mpsse_immediate(FtdiMpsse* ftdi_mpsse) {
    if(ftdi_mpsse->callback_immediate) {
        ftdi_mpsse->callback_immediate(ftdi_mpsse->context_immediate);
    }
}
void ftdi_mpsse_state_machine(FtdiMpsse* ftdi_mpsse) {
    ftdi_mpsse->error = FtdiMpsseErrorNone;
    uint8_t data = ftdi_mpsse_get_data_stream(ftdi_mpsse);
    uint8_t gpio_state_io = 0xFF;
    switch(data) {
    case FtdiMpsseCommandsSetBitsLow: // 0x80  Change LSB GPIO output */
        /* Public bridge is hardware-SPI only. GPIO commands may only
         * select/deselect CS; manual SCK/MOSI toggling is blocked. */
        ftdi_mpsse->gpio_state = ftdi_mpsse_get_data_stream(ftdi_mpsse) & FTDI_MPSSE_TB2_CS_BIT;
        /* Consume the FTDI direction byte, but keep the TB2 SPI pin ownership
         * fixed. In particular CS always remains an output with a safe high idle. */
        ftdi_mpsse_get_data_stream(ftdi_mpsse);
        ftdi_mpsse->gpio_mask = FTDI_MPSSE_TB2_GPIO_MASK;
#if TB2_USE_NATIVE_SPI
        if(ftdi_mpsse->tb2_spi) {
            /* CS owns the native transaction. Acquire configures SCK/MOSI/MISO before
             * the external SPI handle asserts PA4 low; release raises PA4 before GPIO
             * ownership is restored. Never preselect the flash through GPIO. */
            if(ftdi_mpsse->gpio_state & FTDI_MPSSE_TB2_CS_BIT) {
                if(tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
                    ftdi_mpsse_native_spi_release(ftdi_mpsse);
                } else {
                    ftdi_mpsse_restore_gpio(ftdi_mpsse);
                }
            } else if(!tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
                if(!tb2_spi_backend_acquire(ftdi_mpsse->tb2_spi)) {
                    ftdi_mpsse_native_spi_failure(ftdi_mpsse, "CS acquire");
                }
            }
            break;
        }
#endif
        if(ftdi_mpsse->gpio_mask_old != ftdi_mpsse->gpio_mask) {
            ftdi_mpsse_gpio_set_direction(ftdi_mpsse);
            ftdi_mpsse->gpio_mask_old = ftdi_mpsse->gpio_mask;
        }
        ftdi_mpsse_gpio_set(ftdi_mpsse);
        //Write to GPIO
        break;
    case FtdiMpsseCommandsSetBitsHigh: // 0x82  Change MSB GPIO output */
        //Todo not supported
        ftdi_mpsse_get_data_stream(ftdi_mpsse);
        ftdi_mpsse_get_data_stream(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsGetBitsLow: // 0x81  Get LSB GPIO output */
        //Read GPIO
        gpio_state_io = ftdi_mpsse_gpio_get();
        ftdi_mpssse_set_data_stream(ftdi_mpsse, &gpio_state_io, 1);
        break;
    case FtdiMpsseCommandsGetBitsHigh: // 0x83  Get MSB GPIO output */
        //Todo not supported
        gpio_state_io = 0xFF;
        ftdi_mpssse_set_data_stream(ftdi_mpsse, &gpio_state_io, 1);
        break;
    case FtdiMpsseCommandsSendImmediate: // 0x87  Send immediate */
        //tx data to host callback
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsWriteBytesPveMsb: // 0x10  Write bytes with positive edge clock, MSB first */
        //spi mode 1,3
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_get_data(ftdi_mpsse);
        ftdi_mpsse_data_write_bytes_pve_msb(ftdi_mpsse->data_buf, ftdi_mpsse->data_buf_count_byte);
        break;
    case FtdiMpsseCommandsWriteBytesNveMsb: // 0x11  Write bytes with negative edge clock, MSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_get_data(ftdi_mpsse);
#if TB2_USE_NATIVE_SPI
        if(ftdi_mpsse_native_spi_selected(ftdi_mpsse)) {
            if(ftdi_mpsse_native_spi_begin(ftdi_mpsse)) {
                if(!tb2_spi_backend_tx(
                       ftdi_mpsse->tb2_spi,
                       ftdi_mpsse->data_buf,
                       ftdi_mpsse->data_buf_count_byte)) {
                    ftdi_mpsse_native_spi_failure(ftdi_mpsse, "TX");
                }
                break;
            }
            /* A selected native backend must never silently fall back to GPIO bit-banging. */
            FURI_LOG_E(TAG, "TB2 native SPI selected but could not start TX");
            break;
        }
#endif
        ftdi_mpsse_data_write_bytes_nve_msb(ftdi_mpsse->data_buf, ftdi_mpsse->data_buf_count_byte);
        break;
    case FtdiMpsseCommandsWriteBitsPveMsb: // 0x12  Write bits with positive edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_skeep_data(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsWriteBitsNveMsb: // 0x13  Write bits with negative edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_skeep_data(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsWriteBytesPveLsb: // 0x18  Write bytes with positive edge clock, LSB first */
        //spi mode 1,3
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_get_data(ftdi_mpsse);
        ftdi_mpsse_data_write_bytes_pve_lsb(ftdi_mpsse->data_buf, ftdi_mpsse->data_buf_count_byte);
        break;
    case FtdiMpsseCommandsWriteBytesNveLsb: // 0x19  Write bytes with negative edge clock, LSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_get_data(ftdi_mpsse);
        ftdi_mpsse_data_write_bytes_nve_lsb(ftdi_mpsse->data_buf, ftdi_mpsse->data_buf_count_byte);
        break;
    case FtdiMpsseCommandsWriteBitsPveLsb: // 0x1a  Write bits with positive edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_skeep_data(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsWriteBitsNveLsb: // 0x1b  Write bits with negative edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        ftdi_mpsse_skeep_data(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsReadBytesPveMsb: // 0x20  Read bytes with positive edge clock, MSB first */
        //spi mode 1,3 (TB2 native bridge always uses the external mode-0 hardware profile)
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        if(ftdi_mpsse->data_size >= FTDI_MPSSE_TX_RX_SIZE) {
            ftdi_mpsse->error = FtdiMpsseErrorTxOverflow;
            FURI_LOG_E(TAG, "Tx buffer overflow");
        } else {
            ftdi_mpsse->data_size++;
#if TB2_USE_NATIVE_SPI
            if(ftdi_mpsse->tb2_spi && tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
                if(!tb2_spi_backend_rx(
                       ftdi_mpsse->tb2_spi, ftdi_mpsse->data_buf, ftdi_mpsse->data_size)) {
                    memset(ftdi_mpsse->data_buf, 0, ftdi_mpsse->data_size);
                    ftdi_mpsse_native_spi_failure(ftdi_mpsse, "RX");
                }
            } else
#endif
            {
                ftdi_mpsse_data_read_bytes_pve_msb(ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            }
            ftdi_mpssse_set_data_stream(ftdi_mpsse, ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpsse_immediate(ftdi_mpsse);
        }
        break;
    case FtdiMpsseCommandsReadBytesNveMsb: // 0x24  Read bytes with negative edge clock, MSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        if(ftdi_mpsse->data_size >= FTDI_MPSSE_TX_RX_SIZE) {
            ftdi_mpsse->error = FtdiMpsseErrorTxOverflow;
            FURI_LOG_E(TAG, "Tx buffer overflow");
        } else {
            ftdi_mpsse->data_size++;
#if TB2_USE_NATIVE_SPI
            if(ftdi_mpsse->tb2_spi && tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
                if(!tb2_spi_backend_rx(
                       ftdi_mpsse->tb2_spi, ftdi_mpsse->data_buf, ftdi_mpsse->data_size)) {
                    memset(ftdi_mpsse->data_buf, 0, ftdi_mpsse->data_size);
                    ftdi_mpsse_native_spi_failure(ftdi_mpsse, "RX");
                }
            } else
#endif
            {
                ftdi_mpsse_data_read_bytes_nve_msb(ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            }
            ftdi_mpssse_set_data_stream(ftdi_mpsse, ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpsse_immediate(ftdi_mpsse);
        }

        //write data
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsReadBitsPveMsb: // 0x22  Read bits with positive edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //write data
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsReadBitsNveMsb: // 0x26  Read bits with negative edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //write data
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsReadBytesPveLsb: // 0x28  Read bytes with positive edge clock, LSB first */
        //spi mode 1,3
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        if(ftdi_mpsse->data_size >= FTDI_MPSSE_TX_RX_SIZE) {
            ftdi_mpsse->error = FtdiMpsseErrorTxOverflow;
            FURI_LOG_E(TAG, "Tx buffer overflow");
        } else {
            ftdi_mpsse->data_size++;
            ftdi_mpsse_data_read_bytes_pve_lsb(ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpssse_set_data_stream(ftdi_mpsse, ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpsse_immediate(ftdi_mpsse);
        }
        break;
    case FtdiMpsseCommandsReadBytesNveLsb: // 0x2c  Read bytes with negative edge clock, LSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        if(ftdi_mpsse->data_size >= FTDI_MPSSE_TX_RX_SIZE) {
            ftdi_mpsse->error = FtdiMpsseErrorTxOverflow;
            FURI_LOG_E(TAG, "Tx buffer overflow");
        } else {
            ftdi_mpsse->data_size++;
            ftdi_mpsse_data_read_bytes_nve_lsb(ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpssse_set_data_stream(ftdi_mpsse, ftdi_mpsse->data_buf, ftdi_mpsse->data_size);
            ftdi_mpsse_immediate(ftdi_mpsse);
        }
        break;
    case FtdiMpsseCommandsReadBitsPveLsb: // 0x2a  Read bits with positive edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //write data
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsReadBitsNveLsb: // 0x2e  Read bits with negative edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //write data
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBytesPveNveMsb: // 0x31  Read/Write bytes with positive edge clock, MSB first */
        //spi mode 1,3
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_get_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBytesNvePveMsb: // 0x34  Read/Write bytes with negative edge clock, MSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_get_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBitsPveNveMsb: // 0x33  Read/Write bits with positive edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_skeep_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBitsNvePveMsb: // 0x36  Read/Write bits with negative edge clock, MSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_skeep_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBytesPveNveLsb: // 0x39  Read/Write bytes with positive edge clock, LSB first */
        //spi mode 1,3
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_get_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBytesNvePveLsb: // 0x3c  Read/Write bytes with negative edge clock, LSB first */
        //spi mode 0,2
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_get_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBitsPveNveLsb: // 0x3b  Read/Write bits with positive edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_skeep_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsRwBitsNvePveLsb: // 0x3e  Read/Write bits with negative edge clock, LSB first */
        //not supported
        ftdi_mpsse->data_size = ftdi_mpsse_get_data_size(ftdi_mpsse);
        //read data
        //ftdi_mpsse_skeep_data(ftdi_mpsse);
        //ftdi_mpssse_set_data_stream(ftdi_mpsse, 0xFF, ftdi_mpsse->data_size);
        break;
    case FtdiMpsseCommandsWriteBitsTmsPve: // 0x4a  Write bits with TMS, positive edge clock */
        //not supported
        break;
    case FtdiMpsseCommandsWriteBitsTmsNve: // 0x4b  Write bits with TMS, negative edge clock */
        //not supported
        break;
    case FtdiMpsseCommandsRwBitsTmsPvePve: // 0x6a  Read/Write bits with TMS, positive edge clock, MSB first */
        //not supported
        break;
    case FtdiMpsseCommandsRwBitsTmsPveNve: // 0x6b  Read/Write bits with TMS, positive edge clock, MSB first */
        //not supported
        break;
    case FtdiMpsseCommandsRwBitsTmsNvePve: // 0x6e  Read/Write bits with TMS, negative edge clock, MSB first */
        //not supported
        break;
    case FtdiMpsseCommandsRwBitsTmsNveNve: // 0x6f  Read/Write bits with TMS, negative edge clock, MSB first */
        //not supported
        break;
    case FtdiMpsseCommandsLoopbackStart: // 0x84  Enable loopback */
        ftdi_mpsse->is_loopback = true;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsLoopbackEnd: // 0x85  Disable loopback */
        ftdi_mpsse->is_loopback = false;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsSetTckDivisor: // 0x86  Set clock */
    {
        uint8_t low = ftdi_mpsse_get_data_stream(ftdi_mpsse);
        uint8_t high = ftdi_mpsse_get_data_stream(ftdi_mpsse);
        if(ftdi_mpsse->error == FtdiMpsseErrorNone) {
            ftdi_mpsse->divisor = (uint16_t)low | ((uint16_t)high << 8);
            ftdi_mpsse->divisor_valid = true;
            ftdi_mpsse_update_clock(ftdi_mpsse);
        }
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    }
    case FtdiMpsseCommandsDisDiv5: // 0x8a  Disable divide by 5 */
        ftdi_mpsse->is_div5 = false;
        ftdi_mpsse_update_clock(ftdi_mpsse);
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsEnDiv5: // 0x8b  Enable divide by 5 */
        ftdi_mpsse->is_div5 = true;
        ftdi_mpsse_update_clock(ftdi_mpsse);
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsEnableClk3Phase: // 0x8c  Enable 3-phase data clocking (I2C) */
        ftdi_mpsse->is_clk3phase = true;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsDisableClk3Phase: // 0x8d  Disable 3-phase data clocking */
        ftdi_mpsse->is_clk3phase = false;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsClkBitsNoData: // 0x8e  Allows JTAG clock to be output w/o data */
        //not supported
        break;
    case FtdiMpsseCommandsClkBytesNoData: // 0x8f  Allows JTAG clock to be output w/o data */
        //not supported
        break;
    case FtdiMpsseCommandsClkWaitOnHigh: // 0x94  Clock until GPIOL1 is high */
        //not supported
        break;
    case FtdiMpsseCommandsClkWaitOnLow: // 0x95  Clock until GPIOL1 is low */
        //not supported
        break;
    case FtdiMpsseCommandsEnableClkAdaptive: // 0x96  Enable JTAG adaptive clock for ARM */
        ftdi_mpsse->is_adaptive = true;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsDisableClkAdaptive: // 0x97  Disable JTAG adaptive clock */
        ftdi_mpsse->is_adaptive = false;
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    case FtdiMpsseCommandsClkCountWaitOnHigh: // 0x9c  Clock byte cycles until GPIOL1 is high */
        //not supported
        break;
    case FtdiMpsseCommandsClkCountWaitOnLow: // 0x9d  Clock byte cycles until GPIOL1 is low */
        //not supported
        break;
    case FtdiMpsseCommandsDriveZero: // 0x9e  Drive-zero mode */
        //not supported
        break;
    case FtdiMpsseCommandsWaitOnHigh: // 0x88  Wait until GPIOL1 is high */
        //not supported
        break;
    case FtdiMpsseCommandsWaitOnLow: // 0x89  Wait until GPIOL1 is low */
        //not supported
        break;
    case FtdiMpsseCommandsReadShort: // 0x90  Read short */
        //not supported
        break;
    case FtdiMpsseCommandsReadExtended: // 0x91  Read extended */
        //not supported
        break;
    case FtdiMpsseCommandsWriteShort: // 0x92  Write short */
        //not supported
        break;
    case FtdiMpsseCommandsWriteExtended: // 0x93  Write extended */
        //not supported
        break;

    case TB2_MPSSE_CMD_HW_JEDEC: {
        /* TB2-only diagnostic/gate. Reply: status byte + three JEDEC bytes.
         * status bit0 = transport completed, bit1 = ID exactly EF 40 18. */
        uint8_t response[4] = {0, 0, 0, 0};
#if TB2_USE_NATIVE_SPI
        bool ok = false;
        if(ftdi_mpsse->tb2_spi && !tb2_spi_backend_is_acquired(ftdi_mpsse->tb2_spi)) {
            ok = tb2_spi_backend_probe_jedec(ftdi_mpsse->tb2_spi, &response[1]);
        }
        if(ok) response[0] |= 0x01;
        if(ok && tb2_spi_backend_is_verified(ftdi_mpsse->tb2_spi)) response[0] |= 0x02;
        /* The direct probe temporarily owns the SPI pins. Restore MPSSE GPIO idle/directions
         * before returning control to the normal command stream. */
        ftdi_mpsse_restore_gpio(ftdi_mpsse);
#endif
        ftdi_mpssse_set_data_stream(ftdi_mpsse, response, sizeof(response));
        ftdi_mpsse_immediate(ftdi_mpsse);
        break;
    }

    default:
        break;
    }
    if(ftdi_mpsse->error != FtdiMpsseErrorNone) ftdi_mpsse_native_spi_reset(ftdi_mpsse);
}
