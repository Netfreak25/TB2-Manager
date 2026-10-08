#include "tb2_spi_backend.h"

#include <furi.h>
#include <furi_hal.h>
#include <stdlib.h>
#include <string.h>
#include <stm32wbxx_ll_rcc.h>
#include <stm32wbxx_ll_spi.h>

#define TAG                         "TB2_SPI"
#define TB2_SPI_TRANSFER_TIMEOUT_MS (1000U)

struct Tb2SpiBackend {
    bool initialized;
    bool acquired;
    bool insomnia;
    bool verified;
    uint8_t last_jedec[3];
    Tb2SpiClockStatus clock;
};

/* External SPI1 is clocked from APB2 (no timer clock multiplier). */
static uint32_t tb2_spi_kernel_hz(void) {
    switch(LL_RCC_GetAPB2Prescaler()) {
    case LL_RCC_APB2_DIV_2:
        return SystemCoreClock / 2U;
    case LL_RCC_APB2_DIV_4:
        return SystemCoreClock / 4U;
    case LL_RCC_APB2_DIV_8:
        return SystemCoreClock / 8U;
    case LL_RCC_APB2_DIV_16:
        return SystemCoreClock / 16U;
    default:
        return SystemCoreClock;
    }
}

static bool tb2_spi_clock_select(uint32_t kernel, uint32_t requested, uint32_t* index) {
    for(uint32_t i = 0; i < 8U; ++i) {
        /* Compare without truncating a fractional hardware frequency. */
        if((uint64_t)requested * (2U << i) >= kernel) {
            *index = i;
            return true;
        }
    }
    return false;
}

bool tb2_spi_backend_set_clock(Tb2SpiBackend* backend, uint32_t requested_hz) {
    uint32_t index;
    backend->clock.requested_hz = requested_hz;
    backend->clock.clock_error |= !tb2_spi_clock_select(tb2_spi_kernel_hz(), requested_hz, &index);
    return !backend->clock.clock_error;
}

void tb2_spi_backend_reset_clock(Tb2SpiBackend* backend) {
    backend->clock.requested_hz = 0;
    backend->clock.applied_hz = 0;
    /* A nonrepresentable request is fatal for this bridge session. */
}

Tb2SpiClockStatus tb2_spi_backend_clock_status(const Tb2SpiBackend* backend) {
    return backend->clock;
}

Tb2SpiBackend* tb2_spi_backend_alloc(uint32_t default_hz) {
    Tb2SpiBackend* backend = malloc(sizeof(Tb2SpiBackend));
    if(!backend) return NULL;
    memset(backend, 0, sizeof(Tb2SpiBackend));
    backend->clock.default_hz = tb2_spi_default_clock_valid(default_hz) ? default_hz :
                                                                          TB2_SPI_DEFAULT_HZ;
    return backend;
}

bool tb2_spi_backend_init(Tb2SpiBackend* backend) {
    if(!backend) return false;
    if(backend->initialized) return true;

    furi_hal_power_insomnia_enter();
    backend->insomnia = true;
    furi_hal_spi_bus_handle_init(&furi_hal_spi_bus_handle_external);
    backend->initialized = true;
    FURI_LOG_I(TAG, "native SPI initialized");
    return true;
}

bool tb2_spi_backend_acquire(Tb2SpiBackend* backend) {
    if(!backend || backend->clock.clock_error) return false;
    if(backend->acquired) return true;
    if(!tb2_spi_backend_init(backend)) return false;

    static const uint32_t prescalers[] = {
        LL_SPI_BAUDRATEPRESCALER_DIV2,
        LL_SPI_BAUDRATEPRESCALER_DIV4,
        LL_SPI_BAUDRATEPRESCALER_DIV8,
        LL_SPI_BAUDRATEPRESCALER_DIV16,
        LL_SPI_BAUDRATEPRESCALER_DIV32,
        LL_SPI_BAUDRATEPRESCALER_DIV64,
        LL_SPI_BAUDRATEPRESCALER_DIV128,
        LL_SPI_BAUDRATEPRESCALER_DIV256,
    };
    uint32_t kernel = tb2_spi_kernel_hz();
    uint32_t requested = backend->clock.requested_hz ? backend->clock.requested_hz :
                                                       backend->clock.default_hz;
    uint32_t index;
    if(!tb2_spi_clock_select(kernel, requested, &index)) {
        backend->clock.clock_error = true;
        return false;
    }
    furi_hal_spi_acquire(&furi_hal_spi_bus_handle_external);
    /* Acquire restores the SDK profile. Reapply before the first clock edge. */
    LL_SPI_Disable(furi_hal_spi_bus_handle_external.bus->spi);
    LL_SPI_SetBaudRatePrescaler(furi_hal_spi_bus_handle_external.bus->spi, prescalers[index]);
    LL_SPI_Enable(furi_hal_spi_bus_handle_external.bus->spi);
    backend->clock.applied_hz = kernel / (2U << index);
    backend->acquired = true;
    return true;
}

void tb2_spi_backend_release(Tb2SpiBackend* backend) {
    if(!backend || !backend->acquired) return;
    furi_hal_spi_release(&furi_hal_spi_bus_handle_external);
    backend->acquired = false;
}

bool tb2_spi_backend_tx(Tb2SpiBackend* backend, const uint8_t* data, size_t size) {
    if(!backend || backend->clock.clock_error || !backend->acquired || (!data && size))
        return false;
    if(!size) return true;
    return furi_hal_spi_bus_tx(
        &furi_hal_spi_bus_handle_external, data, size, TB2_SPI_TRANSFER_TIMEOUT_MS);
}

bool tb2_spi_backend_rx(Tb2SpiBackend* backend, uint8_t* data, size_t size) {
    if(!backend || backend->clock.clock_error || !backend->acquired || !data || !size)
        return false;
    return furi_hal_spi_bus_rx(
        &furi_hal_spi_bus_handle_external, data, size, TB2_SPI_TRANSFER_TIMEOUT_MS);
}

bool tb2_spi_backend_is_acquired(const Tb2SpiBackend* backend) {
    return backend && backend->acquired;
}

bool tb2_spi_backend_is_verified(const Tb2SpiBackend* backend) {
    return backend && backend->verified;
}

void tb2_spi_backend_invalidate(Tb2SpiBackend* backend) {
    if(!backend) return;
    backend->verified = false;
}

bool tb2_spi_backend_probe_jedec(Tb2SpiBackend* backend, uint8_t jedec[3]) {
    if(!backend || !jedec || backend->acquired) return false;

    static const uint8_t expected[3] = {0xEF, 0x40, 0x18};
    const uint8_t command = 0x9F;
    bool ok = tb2_spi_backend_acquire(backend);
    if(ok) ok = tb2_spi_backend_tx(backend, &command, 1);
    if(ok) ok = tb2_spi_backend_rx(backend, jedec, 3);
    tb2_spi_backend_release(backend);

    if(!ok) {
        memset(jedec, 0, 3);
        backend->verified = false;
        FURI_LOG_E(TAG, "direct JEDEC transport failed");
        return false;
    }

    memcpy(backend->last_jedec, jedec, sizeof(backend->last_jedec));
    backend->verified = memcmp(jedec, expected, sizeof(expected)) == 0;
    if(backend->verified) {
        FURI_LOG_I(TAG, "direct JEDEC verified: EF 40 18");
    }
    return true;
}

void tb2_spi_backend_free(Tb2SpiBackend* backend) {
    if(!backend) return;

    tb2_spi_backend_release(backend);
    if(backend->initialized) {
        furi_hal_spi_bus_handle_deinit(&furi_hal_spi_bus_handle_external);
        backend->initialized = false;
    }
    if(backend->insomnia) {
        furi_hal_power_insomnia_exit();
        backend->insomnia = false;
    }
    free(backend);
}
