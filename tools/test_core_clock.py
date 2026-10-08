"""Run real bridge clock/backend/parser functions against a host SPI fake.

Requires Python and a C compiler (CC or cc). No chip, image or private harness.
The stream fake supplies each divisor byte separately and can time out mid-command.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    """Extract a C function verbatim, including its declaration."""
    match = re.search(r"^.*\b" + name + r"\([^;]*?\)\s*\{", source, re.MULTILINE)
    if not match:
        raise ValueError(name)
    start = match.start()
    end = match.end()
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


FAKE = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FURI_LOG_I(...) ((void)0)
#define FURI_LOG_E(...) ((void)0)
#define LL_RCC_APB2_DIV_2 2
#define LL_RCC_APB2_DIV_4 4
#define LL_RCC_APB2_DIV_8 8
#define LL_RCC_APB2_DIV_16 16
#define LL_SPI_BAUDRATEPRESCALER_DIV2 2
#define LL_SPI_BAUDRATEPRESCALER_DIV4 4
#define LL_SPI_BAUDRATEPRESCALER_DIV8 8
#define LL_SPI_BAUDRATEPRESCALER_DIV16 16
#define LL_SPI_BAUDRATEPRESCALER_DIV32 32
#define LL_SPI_BAUDRATEPRESCALER_DIV64 64
#define LL_SPI_BAUDRATEPRESCALER_DIV128 128
#define LL_SPI_BAUDRATEPRESCALER_DIV256 256
static uint32_t SystemCoreClock=64000000, apb=1, prescaler;
static unsigned acquires, releases, clocks, tx_bytes, rx_bytes;
static bool active;
static struct { int spi; } bus;
static struct { typeof(bus)* bus; } furi_hal_spi_bus_handle_external={&bus};
#define LL_RCC_GetAPB2Prescaler() apb
#define furi_hal_power_insomnia_enter() ((void)0)
#define furi_hal_power_insomnia_exit() ((void)0)
#define furi_hal_spi_bus_handle_init(h) ((void)(h))
#define furi_hal_spi_bus_handle_deinit(h) ((void)(h))
#define furi_hal_spi_acquire(h) ((void)(h), assert(!active), active=true, acquires++, prescaler=32)
#define furi_hal_spi_release(h) ((void)(h), assert(active), active=false, releases++)
#define LL_SPI_Disable(s) ((void)(s))
#define LL_SPI_Enable(s) ((void)(s))
#define LL_SPI_SetBaudRatePrescaler(s,p) ((void)(s), assert(active), prescaler=(p), clocks++)
static bool furi_hal_spi_bus_tx(const void* h,const uint8_t* d,size_t n,unsigned t) {
    (void)h;(void)d;(void)t;assert(active);tx_bytes+=n;return true;
}
static bool furi_hal_spi_bus_rx(const void* h,uint8_t* d,size_t n,unsigned t) {
    (void)h;(void)t;assert(active);rx_bytes+=n;memset(d,0xA5,n);return true;
}
'''

PARSER_FAKE = r'''
enum { FtdiMpsseErrorNone, FtdiMpsseErrorTimeout };
enum { FtdiMpsseCommandsSetTckDivisor=0x86, FtdiMpsseCommandsDisDiv5=0x8A,
       FtdiMpsseCommandsEnDiv5=0x8B };
#define FTDI_MPSSE_TIMEOUT 5000
typedef struct { uint8_t bytes[2]; unsigned available,pos; } Stream;
typedef struct { Tb2SpiBackend* tb2_spi; bool is_div5, divisor_valid;
                 uint16_t divisor; int error; Stream* ftdi; } FtdiMpsse;
static unsigned immediate;
static unsigned ftdi_get_rx_buf(Stream* s,uint8_t* data,unsigned n,unsigned timeout) {
    assert(n==1 && timeout==FTDI_MPSSE_TIMEOUT);
    if(s->pos==s->available) return 0;
    *data=s->bytes[s->pos++];return 1;
}
static void ftdi_mpsse_native_spi_reset(FtdiMpsse* m) { tb2_spi_backend_release(m->tb2_spi); }
static void ftdi_mpsse_immediate(FtdiMpsse* m) {(void)m;immediate++;}
'''

MAIN = r'''
static void command(FtdiMpsse* m,unsigned op,uint16_t divisor,unsigned available) {
    Stream stream={{divisor & 255,divisor >> 8},available,0};
    m->ftdi=&stream;m->error=0;parse(m,op);
}
int main(void) {
    uint32_t index;
    assert(tb2_spi_clock_select(64000000,3750000,&index) && index==4);
    assert(tb2_spi_clock_select(64000000,5000000,&index) && index==3);
    assert(tb2_spi_clock_select(64000000,30000000,&index) && index==1);
    assert(tb2_spi_clock_select(64000000,250000,&index) && index==7);
    assert(!tb2_spi_clock_select(64000000,249999,&index));
    assert(!tb2_spi_clock_select(64000001,250000,&index));
    for(unsigned d=2;d<=16;d*=2) {
        Tb2SpiBackend* b=tb2_spi_backend_alloc(d*1000000);
        FtdiMpsse m={.tb2_spi=b};ftdi_mpsse_session_reset(&m);
        command(&m,0x8A,0,0);
        assert(!b->clock.requested_hz);
        assert(tb2_spi_backend_acquire(b));assert(b->clock.applied_hz==d*1000000);
        unsigned edges=acquires+releases, old_clocks=clocks;
        command(&m,0x86,5,2); /* 60 MHz / 12 = 5 MHz => 4 MHz */
        assert(b->clock.requested_hz==5000000);
        assert(acquires+releases==edges && clocks==old_clocks);
        assert(tb2_spi_backend_acquire(b));assert(clocks==old_clocks);
        uint8_t bytes[16]={0};
        assert(tb2_spi_backend_tx(b,bytes,16));assert(tb2_spi_backend_rx(b,bytes,16));
        tb2_spi_backend_release(b);assert(tb2_spi_backend_acquire(b));
        assert(prescaler==16 && b->clock.applied_hz==4000000);
        tb2_spi_backend_release(b);
        command(&m,0x8B,0,0);assert(b->clock.requested_hz==1000000);
        assert(tb2_spi_backend_acquire(b));assert(prescaler==64);
        tb2_spi_backend_release(b);
        command(&m,0x8A,0,0);command(&m,0x86,7,2);
        assert(tb2_spi_backend_acquire(b));assert(b->clock.applied_hz==2000000);
        tb2_spi_backend_release(b);
        ftdi_mpsse_session_reset(&m);
        command(&m,0x86,0x1234,1); /* Missing high byte cannot change default. */
        assert(!b->clock.requested_hz && !m.divisor_valid);
        ftdi_mpsse_session_reset(&m);
        assert(tb2_spi_backend_acquire(b));assert(b->clock.applied_hz==d*1000000);
        ftdi_mpsse_session_reset(&m);assert(!active);
        command(&m,0x8A,0,0);command(&m,0x86,0xFFFF,2);
        assert(m.divisor==65535 && ftdi_mpsse_clock_failed(&m));
        assert(b->clock.requested_hz==457);
        assert(!tb2_spi_backend_acquire(b));
        assert(!tb2_spi_backend_tx(b,bytes,1));
        ftdi_mpsse_session_reset(&m);assert(ftdi_mpsse_clock_failed(&m));
        tb2_spi_backend_free(b);
    }
    apb=2;
    Tb2SpiBackend* b=tb2_spi_backend_alloc(4000000);
    assert(tb2_spi_backend_acquire(b));assert(prescaler==8);
    tb2_spi_backend_free(b);
    assert(acquires==releases && tx_bytes==64 && rx_bytes==64);
    puts("PASS: clock mapping, full divisor, fragmented bytes/timeout, CS deferral, reacquire, reset, raw TX/RX");
}
'''

PREFERENCES_FAKE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tb2_spi_backend.h"
#define FLIPTDI_CONFIG_PATH "test.conf"
#define FLIPTDI_CONFIG_TYPE "TB2 Core Flasher"
#define FLIPTDI_CONFIG_VERSION 1U
typedef struct {bool exists,write_fail,read_fail,close_fail; uint32_t version,mhz; char type[40];} Storage;
typedef Storage FlipperFormat;
typedef struct {char text[40];} FuriString;
static unsigned opens,closes;
static FlipperFormat* flipper_format_file_alloc(Storage* s) {return s;}
static FuriString* furi_string_alloc(void) {return calloc(1,sizeof(FuriString));}
static void flipper_format_free(FlipperFormat* f) {(void)f;}
static void furi_string_free(FuriString* s) {free(s);}
static const char* furi_string_get_cstr(FuriString* s) {return s->text;}
static bool flipper_format_file_open_existing(FlipperFormat* f,const char* p) {
    assert(!strcmp(p,FLIPTDI_CONFIG_PATH));opens++;return f->exists && !f->read_fail;
}
static bool flipper_format_file_open_always(FlipperFormat* f,const char* p) {
    assert(!strcmp(p,FLIPTDI_CONFIG_PATH));opens++;if(f->write_fail)return false;
    f->exists=true;return true;
}
static bool flipper_format_file_close(FlipperFormat* f) {closes++;return !f->close_fail;}
static bool flipper_format_read_header(FlipperFormat* f,FuriString* s,uint32_t* v) {
    strcpy(s->text,f->type);*v=f->version;return true;
}
static bool flipper_format_write_header_cstr(FlipperFormat* f,const char* s,uint32_t v) {
    strcpy(f->type,s);f->version=v;return !f->write_fail;
}
static bool flipper_format_read_uint32(FlipperFormat* f,const char* k,uint32_t* v,unsigned n) {
    assert(n==1 && !strcmp(k,"Default SPI MHz"));*v=f->mhz;return true;
}
static bool flipper_format_write_uint32(FlipperFormat* f,const char* k,const uint32_t* v,unsigned n) {
    assert(n==1 && !strcmp(k,"Default SPI MHz"));f->mhz=*v;return !f->write_fail;
}
'''

PREFERENCES_MAIN = r'''
int main(void) {
    Storage storage={0};uint32_t hz=0;
    assert(!fliptdi_load_clock(&storage,&hz) && hz==2000000);
    for(unsigned mhz=2;mhz<=16;mhz*=2) {
        unsigned before=opens;
        assert(fliptdi_save_clock(&storage,mhz*1000000));
        assert(opens==before+2); /* Save must read back through a new handle. */
        hz=0;assert(fliptdi_load_clock(&storage,&hz) && hz==mhz*1000000);
    }
    storage.version=99;assert(!fliptdi_load_clock(&storage,&hz) && hz==2000000);
    storage.version=1;storage.mhz=3;assert(!fliptdi_load_clock(&storage,&hz) && hz==2000000);
    strcpy(storage.type,"bad");assert(!fliptdi_load_clock(&storage,&hz));
    storage.write_fail=true;assert(!fliptdi_save_clock(&storage,4000000));
    storage.write_fail=false;storage.close_fail=true;assert(!fliptdi_save_clock(&storage,4000000));
    storage.close_fail=false;storage.read_fail=true;assert(!fliptdi_save_clock(&storage,4000000));
    assert(!fliptdi_save_clock(&storage,3000000));
    assert(opens==closes);
    puts("PASS: independent 2/4/8/16 MHz preferences, reopen/readback, missing/corrupt config, save failures");
}
'''

PENDING_MAIN = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ftdi_usb_tx.h"
static unsigned fills,submits;
static uint16_t fill(void* ctx,uint8_t* p,uint16_t capacity) {
    (void)ctx;assert(capacity>=4);fills++;memcpy(p,"data",4);return 4;
}
static bool submit(void* ctx,const uint8_t* p,uint16_t len) {
    (void)ctx;assert(len==4 && !memcmp(p,"data",4));return ++submits==3;
}
int main(void) {
    FtdiUsbTxState s={0};uint8_t packet[64];
    assert(ftdi_usb_tx_attempt(&s,packet,64,fill,NULL,submit,NULL,1)==FtdiUsbTxRetry);
    assert(ftdi_usb_tx_attempt(&s,packet,64,fill,NULL,submit,NULL,1)==FtdiUsbTxDeferred);
    assert(ftdi_usb_tx_attempt(&s,packet,64,fill,NULL,submit,NULL,1)==FtdiUsbTxSubmitted);
    assert(fills==1 && submits==3 && !s.pending_length);
    puts("PASS: USB submit retries retain the same payload without consuming more bytes");
}
'''


def main():
    source = ROOT / "src/fliptdi"
    backend = (source / "tb2_spi_backend.c").read_text()
    backend = re.sub(r"^#include.*$", "", backend, flags=re.MULTILINE)
    mpsse = (source / "ftdi_mpsse.c").read_text()
    cases = mpsse[mpsse.index("    case FtdiMpsseCommandsSetTckDivisor:") :
                  mpsse.index("    case FtdiMpsseCommandsEnableClk3Phase:")]
    parser = "\n".join(function(mpsse, name) for name in [
        "ftdi_mpsse_session_reset", "ftdi_mpsse_clock_status",
        "ftdi_mpsse_clock_failed", "ftdi_mpsse_update_clock", "ftdi_mpsse_get_data_stream",
    ])
    program = ('#include "tb2_spi_backend.h"\n' + FAKE + backend + PARSER_FAKE + parser +
               "\nstatic void parse(FtdiMpsse* ftdi_mpsse,unsigned cmd) {switch(cmd) {\n" +
               cases + "default: abort();}}\n" + MAIN)
    bridge = (ROOT / "src/fliptdi_bridge.c").read_text()
    preferences = PREFERENCES_FAKE + "\n".join(
        function(bridge, name) for name in ["fliptdi_load_clock", "fliptdi_save_clock"]
    ) + PREFERENCES_MAIN
    with tempfile.TemporaryDirectory(prefix="tb2-clock-") as tmp:
        for name, code in [("clock", program), ("preferences", preferences), ("pending", PENDING_MAIN)]:
            cfile = Path(tmp) / (name + ".c")
            binary = Path(tmp) / name
            cfile.write_text(code)
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                            "-Werror", "-I", str(source), str(cfile), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
    ftdi = (source / "ftdi.c").read_text()
    for name in ["ftdi_reset_purge_rx", "ftdi_reset_purge_tx"]:
        body = function(ftdi, name)
        assert "reset_clock" not in body and "session_reset" not in body
    for name in ["ftdi_reset_sio", "ftdi_set_bitmode"]:
        assert "ftdi_mpsse_session_reset" in function(ftdi, name)
    print("PASS: SIO/bitmode reset routing; RX/TX purge preserves clock")
    back = function(bridge, "fliptdi_back_event")
    assert "save_clock" not in back and "default_hz =" not in back
    assert "fliptdi_show_menu(app)" in back
    assert "app->draft_hz = app->default_hz" in function(bridge, "fliptdi_custom_event")
    print("PASS: Back discards the draft; settings re-entry starts from saved default")


if __name__ == "__main__":
    main()
