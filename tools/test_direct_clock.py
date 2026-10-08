"""Check real direct-SPI prescalers and persisted hardware options without a device."""
import os
import re
import subprocess
import tempfile
from pathlib import Path

from test_core_clock import FAKE, function

ROOT = Path(__file__).resolve().parents[1]

PREFS_FAKE = r'''
#include "ui_store.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {size_t size;} FileInfo;
#define FSE_OK 0
static uint8_t saved[2048];
static size_t saved_size;
static int storage_common_stat(void*s,const char*p,FileInfo*i){(void)s;(void)p;i->size=saved_size;return saved_size?0:1;}
static bool file_info_is_dir(FileInfo*i){(void)i;return false;}
static int ui_read(void*s,const char*p,void*b,size_t n){(void)s;(void)p;assert(n==saved_size);memcpy(b,saved,n);return 1;}
static bool ui_write(void*s,const char*p,const uint8_t*b,size_t n){(void)s;(void)p;assert(n<=sizeof(saved));memcpy(saved,b,n);saved_size=n;return true;}
'''

PREFS_MAIN = r'''
int main(void){
    for(unsigned uid=0;uid<=1;uid++)for(unsigned rate=0;rate<4;rate++){
        Tb2UiPreferences in={0},out;
        in.hardware_options=uid|(rate<<Tb2HardwareSpiShift);
        strcpy(in.output_dir,"/ext/example");
        assert(tb2_ui_preferences_save(NULL,&in));
        memset(&out,0xaa,sizeof(out));
        assert(tb2_ui_preferences_load(NULL,&out));
        assert(out.hardware_options==in.hardware_options);
        assert(!strcmp(in.output_dir,out.output_dir));
    }
    /* A valid CRC cannot make unknown option bits acceptable. */
    saved[8+2U*TB2_JOB_PATH_MAX+2U*TB2_SERVER_HOST_SIZE+5U]=8;
    ui_put32(saved+saved_size-4,tb2_job_crc(saved,saved_size-4));
    Tb2UiPreferences out;
    assert(!tb2_ui_preferences_load(NULL,&out)&&!out.hardware_options);
    puts("PASS: all four rates persist with either UID mode; old 2/4 values retain meaning; unknown bits rejected");
}
'''


def main():
    backend = (ROOT / "src/spi_backend.c").read_text().replace('static bool\n    transfer', 'static bool transfer')
    fake = FAKE.replace(
        'static struct { typeof(bus)* bus; } furi_hal_spi_bus_handle_external={&bus};',
        'typedef struct { typeof(bus)* bus; int cs; } FuriHalSpiBusHandle;\n'
        'static FuriHalSpiBusHandle furi_hal_spi_bus_handle_external={&bus,0};\n'
        '#define furi_hal_gpio_write(pin,value) ((void)(pin),(void)(value))'
    )
    hardware = re.search(r"typedef struct \{.*?\} HardwareSpi;", backend, re.DOTALL).group()
    direct = '#include "spi.h"\n' + fake + hardware + '\n#define SPI_TRANSFER_TIMEOUT_MS 1000U\n'
    direct += '\n'.join(function(backend, name) for name in ['begin', 'end', 'transfer'])
    direct += r'''
int main(void){
    (void)apb;
    for(unsigned speed=0;speed<4;speed++){
        HardwareSpi spi={.bus=&furi_hal_spi_bus_handle_external,.speed=speed};
        for(unsigned retry=0;retry<2;retry++){
            assert(begin(&spi));assert(SystemCoreClock/prescaler==(2000000U<<speed));
            uint8_t tx=0x9f,rx[3];assert(transfer(&spi,&tx,1,rx,3));end(&spi);
        }
    }
    assert(!active&&acquires==releases&&acquires==8);
    puts("PASS: direct 2/4/8/16 MHz prescalers applied after every acquire; read transport retained");
}
'''
    store = (ROOT / "src/ui_store.c").read_text()
    macros = '\n'.join(line for line in store.splitlines() if line.startswith('#define UI_'))
    prefs = PREFS_FAKE + macros + '\n' + '\n'.join(function(store, name) for name in [
        'ui_get32', 'ui_put32', 'ui_path_valid', 'ui_server_values_valid',
        'tb2_ui_preferences_load', 'tb2_ui_preferences_save',
    ]) + PREFS_MAIN
    with tempfile.TemporaryDirectory() as tmp:
        for name, code in [('direct', direct), ('preferences', prefs)]:
            path = Path(tmp) / (name + '.c')
            binary = Path(tmp) / name
            path.write_text(code)
            cmd = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-ffunction-sections', '-Wl,--gc-sections', '-I', str(ROOT / 'src'), str(path)]
            if name == 'preferences':
                cmd += [str(ROOT / 'src/server.c'), str(ROOT / 'src/job.c')]
            subprocess.run(cmd + ['-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    main()
