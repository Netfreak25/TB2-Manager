#pragma once
#include "ftdi.h"

typedef struct FtdiMpsse FtdiMpsse;

/* Fixed FT232H low-byte mapping for the Flipper external SPI bus. The host may
 * change CS state, but it may not change ownership/direction of these pins. */
#define FTDI_MPSSE_TB2_GPIO_MASK (0x0BU)
#define FTDI_MPSSE_TB2_CS_BIT    (0x08U)

typedef void (*FtdiMpsseCallbackImmediate)(void* context);
void ftdi_mpsse_gpio_set_callback(
    FtdiMpsse* ftdi_mpsse,
    FtdiMpsseCallbackImmediate callback,
    void* context);

FtdiMpsse* ftdi_mpsse_alloc(Ftdi* ftdi, uint32_t default_hz);
void ftdi_mpsse_free(FtdiMpsse* ftdi_mpsse);
void ftdi_mpsse_state_machine(FtdiMpsse* ftdi_mpsse);

/** Release/invalidate the TB2 native-SPI bridge after USB/bitmode reset. */
void ftdi_mpsse_native_spi_reset(FtdiMpsse* ftdi_mpsse);

void ftdi_mpsse_session_reset(FtdiMpsse* mpsse);
Tb2SpiClockStatus ftdi_mpsse_clock_status(FtdiMpsse* mpsse);
bool ftdi_mpsse_clock_failed(FtdiMpsse* mpsse);
