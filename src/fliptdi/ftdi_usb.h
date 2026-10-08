#pragma once
#include "tb2_spi_backend.h"
#include <stdbool.h>

typedef struct FtdiUsb FtdiUsb;

FtdiUsb* ftdi_usb_start(uint32_t default_hz);
/** Restore the previous USB interface. Returns only after deinit completed. */
bool ftdi_usb_stop(FtdiUsb* ftdi);

/** Nonblocking worker-serialized snapshot; false means busy. */
bool ftdi_usb_clock_status(FtdiUsb* ftdi, Tb2SpiClockStatus* status);
