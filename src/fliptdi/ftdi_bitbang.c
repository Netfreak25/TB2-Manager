/* Event-driven MPSSE owner for TB2. Generic timed GPIO bit-bang modes are not
 * part of this module, so it does not reserve TIM17. */
#include "ftdi_bitbang.h"
#include "ftdi_gpio.h"

#include <furi.h>
#include <stdlib.h>

typedef enum {
    FtdiBitbangModeOff,
    FtdiBitbangModeMpsse,
} FtdiBitbangMode;

enum {
    WorkerEventStop = 1U << 0,
    WorkerEventData = 1U << 1,
    WorkerEventAll = WorkerEventStop | WorkerEventData,
};

struct FtdiBitbang {
    FuriThread* worker;
    FuriMutex* mutex;
    Ftdi* ftdi;
    FtdiMpsse* mpsse;
    FtdiBitbangMode mode;
    uint8_t gpio_mask;
};

static int32_t ftdi_bitbang_worker(void* context) {
    FtdiBitbang* bitbang = context;
    for(;;) {
        uint32_t events = furi_thread_flags_wait(WorkerEventAll, FuriFlagWaitAny, FuriWaitForever);
        if(events & WorkerEventStop) break;
        if(events & WorkerEventData) {
            furi_mutex_acquire(bitbang->mutex, FuriWaitForever);
            while(bitbang->mode == FtdiBitbangModeMpsse &&
                  !ftdi_mpsse_clock_failed(bitbang->mpsse) && ftdi_available_rx_buf(bitbang->ftdi))
                ftdi_mpsse_state_machine(bitbang->mpsse);
            furi_mutex_release(bitbang->mutex);
        }
    }
    return 0;
}

FtdiBitbang* ftdi_bitbang_alloc(Ftdi* ftdi, uint32_t default_hz) {
    if(!ftdi) return NULL;
    FtdiBitbang* bitbang = calloc(1, sizeof(*bitbang));
    if(!bitbang) return NULL;
    bitbang->ftdi = ftdi;
    bitbang->mpsse = ftdi_mpsse_alloc(ftdi, default_hz);
    bitbang->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    bitbang->worker = furi_thread_alloc_ex("FlipTDIMpsse", 2048, ftdi_bitbang_worker, bitbang);
    if(!bitbang->mpsse || !bitbang->mutex || !bitbang->worker) {
        if(bitbang->worker) furi_thread_free(bitbang->worker);
        if(bitbang->mutex) furi_mutex_free(bitbang->mutex);
        if(bitbang->mpsse) ftdi_mpsse_free(bitbang->mpsse);
        free(bitbang);
        return NULL;
    }
    furi_thread_start(bitbang->worker);
    return bitbang;
}

void ftdi_bitbang_free(FtdiBitbang* bitbang) {
    if(!bitbang) return;
    furi_mutex_acquire(bitbang->mutex, FuriWaitForever);
    bitbang->mode = FtdiBitbangModeOff;
    furi_mutex_release(bitbang->mutex);
    furi_thread_flags_set(furi_thread_get_id(bitbang->worker), WorkerEventStop);
    furi_thread_join(bitbang->worker);
    furi_thread_free(bitbang->worker);
    ftdi_mpsse_free(bitbang->mpsse);
    furi_mutex_free(bitbang->mutex);
    free(bitbang);
}

FtdiMpsse* ftdi_bitbang_get_mpsse_handle(FtdiBitbang* bitbang) {
    return bitbang ? bitbang->mpsse : NULL;
}

void ftdi_bitbang_set_gpio(FtdiBitbang* bitbang, uint8_t gpio_mask) {
    if(!bitbang) return;
    bitbang->gpio_mask = gpio_mask & 0x0FU;
    ftdi_gpio_set_direction(bitbang->gpio_mask);
}

void ftdi_bitbang_enable(FtdiBitbang* bitbang, FtdiBitMode mode) {
    if(bitbang) bitbang->mode = mode.MPSSE ? FtdiBitbangModeMpsse : FtdiBitbangModeOff;
}

void ftdi_bitbang_set_speed(FtdiBitbang* bitbang, uint32_t speed) {
    UNUSED(bitbang);
    UNUSED(speed);
}

void ftdi_bitbang_notify(FtdiBitbang* bitbang) {
    if(bitbang && bitbang->worker)
        furi_thread_flags_set(furi_thread_get_id(bitbang->worker), WorkerEventData);
}

uint8_t ftdi_bitbang_get_gpio(FtdiBitbang* bitbang) {
    UNUSED(bitbang);
    return ftdi_gpio_get_b0() | ftdi_gpio_get_b1() | ftdi_gpio_get_b2() | ftdi_gpio_get_b3();
}

void ftdi_bitbang_lock(FtdiBitbang* bitbang) {
    if(bitbang) furi_mutex_acquire(bitbang->mutex, FuriWaitForever);
}

void ftdi_bitbang_unlock(FtdiBitbang* bitbang) {
    if(bitbang) furi_mutex_release(bitbang->mutex);
}

bool ftdi_bitbang_clock_status(FtdiBitbang* bitbang, Tb2SpiClockStatus* status) {
    if(furi_mutex_acquire(bitbang->mutex, 0) != FuriStatusOk) return false;
    *status = ftdi_mpsse_clock_status(bitbang->mpsse);
    furi_mutex_release(bitbang->mutex);
    return true;
}
