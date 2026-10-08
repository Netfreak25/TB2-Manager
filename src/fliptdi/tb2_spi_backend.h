#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct Tb2SpiBackend Tb2SpiBackend;

#define TB2_SPI_DEFAULT_HZ     2000000U
#define TB2_SPI_FAST_HZ        4000000U
#define TB2_SPI_MAX_DEFAULT_HZ 16000000U

/** Persisted bridge defaults; browser requests use the existing wider mapping. */
static inline bool tb2_spi_default_clock_valid(uint32_t hz) {
    return hz == TB2_SPI_DEFAULT_HZ || hz == TB2_SPI_FAST_HZ || hz == 8000000U ||
           hz == TB2_SPI_MAX_DEFAULT_HZ;
}

typedef struct {
    uint32_t default_hz;
    uint32_t requested_hz; /* Zero until a complete browser divisor arrives. */
    uint32_t applied_hz; /* Zero until the first bus acquire. */
    bool clock_error;
} Tb2SpiClockStatus;

/** Caller serializes these operations with the MPSSE worker. No GPIO changes. */
bool tb2_spi_backend_set_clock(Tb2SpiBackend* backend, uint32_t requested_hz);
void tb2_spi_backend_reset_clock(Tb2SpiBackend* backend);
Tb2SpiClockStatus tb2_spi_backend_clock_status(const Tb2SpiBackend* backend);

/** Allocate a lazy native-SPI backend. Hardware is not touched until first use. */
Tb2SpiBackend* tb2_spi_backend_alloc(uint32_t default_hz);

/** Release any active transaction, deinitialize the external SPI handle and free the backend. */
void tb2_spi_backend_free(Tb2SpiBackend* backend);

/** Ensure the external Flipper SPI handle is initialized. */
bool tb2_spi_backend_init(Tb2SpiBackend* backend);

/** Begin one CS-low transaction using furi_hal_spi_bus_handle_external. */
bool tb2_spi_backend_acquire(Tb2SpiBackend* backend);

/** End the current transaction. Safe to call when no transaction is active. */
void tb2_spi_backend_release(Tb2SpiBackend* backend);

/** Forward bytes while an acquired transaction is active.
 * Flash command policy and transaction planning belong to the browser client. */
bool tb2_spi_backend_tx(Tb2SpiBackend* backend, const uint8_t* data, size_t size);
bool tb2_spi_backend_rx(Tb2SpiBackend* backend, uint8_t* data, size_t size);

/** True while the hardware SPI bus is acquired/CS is asserted. */
bool tb2_spi_backend_is_acquired(const Tb2SpiBackend* backend);

/** True only after a direct hardware-SPI JEDEC probe returned EF 40 18. */
bool tb2_spi_backend_is_verified(const Tb2SpiBackend* backend);

/** Clear the diagnostic JEDEC result after a transport failure or session reset. */
void tb2_spi_backend_invalidate(Tb2SpiBackend* backend);

/**
 * Direct proof-of-concept transaction over the same hardware-SPI path used by TB2 Manager:
 * acquire -> TX 0x9F -> RX 3 -> release.
 *
 * Returns transport success independently of whether the ID matches EF 40 18.
 * This diagnostic result does not gate raw bridge transactions.
 */
bool tb2_spi_backend_probe_jedec(Tb2SpiBackend* backend, uint8_t jedec[3]);
