#include "spi.h"
#include "backend.h"
#include "operation.h"
#include "probe.h"
#include <flipper_application/flipper_application.h>
#include <furi.h>
#include <furi_hal.h>
#include <stm32wbxx_ll_spi.h>
#include <stdio.h>

#define SPI_TRANSFER_TIMEOUT_MS 1000U

typedef struct {
    const FuriHalSpiBusHandle* bus;
    uint8_t speed;
    bool acquired;
} HardwareSpi;

static bool begin(void* context) {
    HardwareSpi* spi = context;
    furi_hal_spi_bus_handle_init(spi->bus);
    furi_hal_spi_acquire(spi->bus);
    spi->acquired = true;
    /* The external handle asserts CS while active. Keep the configured bus
     * acquired for the worker lifetime, but delimit every flash command with
     * explicit CS edges instead of reconfiguring GPIO and SPI each time. */
    furi_hal_gpio_write(spi->bus->cs, true);
    /* Pinned firmware targets use a 64 MHz SPI kernel clock. */
    static const uint32_t prescalers[] = {
        LL_SPI_BAUDRATEPRESCALER_DIV32,
        LL_SPI_BAUDRATEPRESCALER_DIV16,
        LL_SPI_BAUDRATEPRESCALER_DIV8,
        LL_SPI_BAUDRATEPRESCALER_DIV4};
    LL_SPI_Disable(spi->bus->bus->spi);
    LL_SPI_SetBaudRatePrescaler(spi->bus->bus->spi, prescalers[spi->speed]);
    LL_SPI_Enable(spi->bus->bus->spi);
    return true;
}
static void end(void* context) {
    HardwareSpi* spi = context;
    if(spi->acquired) {
        furi_hal_gpio_write(spi->bus->cs, true);
        furi_hal_spi_release(spi->bus);
        spi->acquired = false;
    }
    furi_hal_spi_bus_handle_deinit(spi->bus);
}
static bool
    transfer(void* context, const uint8_t* tx, size_t tx_size, uint8_t* rx, size_t rx_size) {
    HardwareSpi* spi = context;
    if(!spi->acquired || !tx || !tx_size) return false;
    furi_hal_gpio_write(spi->bus->cs, false);
    bool ok = furi_hal_spi_bus_tx(spi->bus, tx, tx_size, SPI_TRANSFER_TIMEOUT_MS);
    if(ok && rx_size)
        ok = rx && furi_hal_spi_bus_rx(spi->bus, rx, rx_size, SPI_TRANSFER_TIMEOUT_MS);
    furi_hal_gpio_write(spi->bus->cs, true);
    return ok;
}
static uint32_t milliseconds(void* context) {
    UNUSED(context);
    return furi_get_tick(); /* Pinned SDK FreeRTOS tick is 1000 Hz. */
}
static void delay(void* context, uint32_t ms) {
    UNUSED(context);
    furi_delay_ms(ms);
}
static int run(Tb2SpiRequest* request) {
    if(request && request->action == Tb2SpiInspectFile) {
        if(!request->io || !request->path || !request->identity) return TB2_PROBE_CHECK_FAILED;
        return tb2_identity_file(
            request->io, request->path, request->directory, request->identity, false);
    }
    HardwareSpi hardware = {
        .bus = &furi_hal_spi_bus_handle_external,
        .speed = request && request->speed < 4 ? request->speed : 0};
    Tb2SpiTransport transport = {
        .context = &hardware,
        .begin = begin,
        .end = end,
        .transfer = transfer,
        .milliseconds = milliseconds,
        .delay = delay};
    return request && request->action == Tb2SpiHeaders ?
               tb2_spi_headers_run(&transport, request) :
               tb2_spi_operation_run(&transport, request);
}
static bool operation(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2Operation* op,
    unsigned access,
    const Tb2JobSpec* spec) {
    if(!io || !directory || !op) return false;
    if(access == Tb2OperationBind) return spec && tb2_operation_bind(io, directory, op, spec);
    if(access == Tb2OperationLoad) return tb2_operation_load(io, directory, op);
    if(access == Tb2OperationSave) return tb2_operation_save(io, directory, op, true);
    if(access != Tb2OperationCreate) return false;
    if(!op->created[0]) {
        DateTime date;
        char text[32];
        furi_hal_rtc_get_datetime(&date);
        int n = snprintf(
            text,
            sizeof(text),
            "%04u%02u%02u%02u%02u%02u",
            date.year,
            date.month,
            date.day,
            date.hour,
            date.minute,
            date.second);
        if(n != TB2_DATE_SIZE - 1) return false;
        snprintf(op->created, sizeof(op->created), "%.*s", TB2_DATE_SIZE - 1, text);
    }
    return tb2_operation_create(io, directory, op);
}
static const Tb2Spi spi = {.run = run, .operation = operation};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_SPI_ID,
    .ep_api_version = TB2_SPI_API,
    .entry_point = &spi};
const FlipperAppPluginDescriptor* tb2_spi_entry(void) {
    return &descriptor;
}
