#pragma once

/* The TB2 integration never falls back to GPIO clocking. Keeping these
 * parser-compatible no-ops makes unsupported FTDI modes harmless while the
 * native hardware-SPI path remains the only path that can reach the flash. */
#include <stdint.h>
#include <string.h>

static inline void ftdi_mpsse_data_write_bytes_nve_msb(uint8_t* data, uint32_t size) {
    (void)data;
    (void)size;
}
static inline void ftdi_mpsse_data_read_bytes_nve_msb(uint8_t* data, uint32_t size) {
    memset(data, 0, size);
}
static inline void ftdi_mpsse_data_write_bytes_nve_lsb(uint8_t* data, uint32_t size) {
    (void)data;
    (void)size;
}
static inline void ftdi_mpsse_data_read_bytes_nve_lsb(uint8_t* data, uint32_t size) {
    memset(data, 0, size);
}
static inline void ftdi_mpsse_data_write_bytes_pve_msb(uint8_t* data, uint32_t size) {
    (void)data;
    (void)size;
}
static inline void ftdi_mpsse_data_read_bytes_pve_msb(uint8_t* data, uint32_t size) {
    memset(data, 0, size);
}
static inline void ftdi_mpsse_data_write_bytes_pve_lsb(uint8_t* data, uint32_t size) {
    (void)data;
    (void)size;
}
static inline void ftdi_mpsse_data_read_bytes_pve_lsb(uint8_t* data, uint32_t size) {
    memset(data, 0, size);
}
