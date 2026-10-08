"""Exercise the real header-only SPI path and its no-store controller route."""
import os
import subprocess
import tempfile
from pathlib import Path

from test_preflight_lease import function

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "spi.h"
#include "probe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint8_t headers[2][32];
static unsigned mode, reads, ends, polls, now, waiting;
static bool cancel;
static void put32(uint8_t* p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void valid(unsigned slot,unsigned major,unsigned minor,unsigned revision,uint32_t build){
    uint8_t* p=headers[slot];memset(p,0,32);put32(p,TB2_MCUBOOT_MAGIC);
    p[9]=4;put32(p+12,4096);p[20]=major;p[21]=minor;p[22]=revision;p[23]=revision>>8;put32(p+24,build);
}
static bool begin(void*c){(void)c;return mode!=8;}
static void end(void*c){(void)c;ends++;}
static bool transfer(void*c,const uint8_t*tx,size_t n,uint8_t*rx,size_t size){
    (void)c;
    if(tx[0]==0x9f){assert(n==1&&size==3);polls++;rx[0]=mode==2?0xff:mode==3?0xc2:0xef;rx[1]=0x40;rx[2]=0x18;return true;}
    if(tx[0]==0x05){assert(n==1&&size==1);rx[0]=mode==4||mode==9?1:0;return mode!=7;}
    assert(tx[0]==0x03&&n==4&&size==32); /* Reject every other opcode/size. */
    uint32_t offset=(uint32_t)tx[1]<<16|(uint32_t)tx[2]<<8|tx[3];
    unsigned slot=offset==TB2_PRIMARY_OFFSET?0:1;assert(slot==0||offset==TB2_SECONDARY_OFFSET);
    reads++;
    if(mode==5&&slot==0)return false;
    memcpy(rx,headers[slot],32);
    if(mode==6)cancel=true;
    return true;
}
static uint32_t milliseconds(void*c){(void)c;return now;}
static void delay(void*c,uint32_t ms){(void)c;now+=ms;if((mode==2||mode==9)&&now>=100)cancel=true;}
static bool cancelled(void*c){(void)c;return cancel;}
static void wait_cb(void*c,bool active){(void)c;waiting=active;}
int main(void){
    Tb2WorkflowIO io={.cancelled=cancelled};
    Tb2SpiTransport bus={.begin=begin,.end=end,.transfer=transfer,.milliseconds=milliseconds,.delay=delay};
    Tb2SlotHeaders result;
    Tb2SpiRequest r={.io=&io,.action=Tb2SpiHeaders,.headers=&result,.waiting=wait_cb};
    for(mode=0;mode<=9;mode++){
        reads=ends=polls=now=waiting=0;cancel=false;memset(&result,0xaa,sizeof(result));
        valid(0,1,6,280,123456);valid(1,0,40,8,0);
        int rc=tb2_spi_headers_run(&bus,&r);
        assert(!waiting&&ends==(mode==8?0:1));
        if(!mode||mode==1){assert(!rc&&reads==2);assert(result.slots[0].revision==280&&result.slots[0].build==123456);assert(result.slots[1].minor==40);}
        else if(mode==2||mode==6||mode==9){assert(rc==TB2_PROBE_CANCELLED);assert(result.slots[1].status==Tb2HeaderNotRead);}
        else if(mode==3){assert(rc==Tb2SpiUnsupported&&!reads);}
        else if(mode==4){assert(rc==Tb2SpiTimeout&&!reads&&now==1000);}
        else if(mode==5){assert(rc==Tb2SpiTransportError&&reads==2);assert(result.slots[0].status==Tb2HeaderReadFailed&&result.slots[1].status==Tb2HeaderValid);}
        else assert(rc==Tb2SpiTransportError&&!reads);
    }
    mode=0;cancel=false;
    memset(headers[0],0xff,32);assert(!tb2_spi_headers_run(&bus,&r));assert(result.slots[0].status==Tb2HeaderEmpty&&result.slots[1].status==Tb2HeaderValid);
    memset(headers[0],0,32);assert(!tb2_spi_headers_run(&bus,&r));assert(result.slots[0].status==Tb2HeaderUnknown);
    valid(0,255,255,65535,0xffffffff);assert(!tb2_spi_headers_run(&bus,&r));assert(result.slots[0].build==0xffffffff);
    put32(headers[0]+12,0xffffffff);assert(!tb2_spi_headers_run(&bus,&r));assert(result.slots[0].status==Tb2HeaderInvalid);
    valid(0,1,2,3,0);reads=0;assert(!tb2_spi_headers_run(&bus,&r));assert(reads==2&&result.slots[0].build==0&&!result.error[0]);
    puts("PASS: two 32-byte reads, no writes/UID/payload/file IO; values, invalid slots, timeout, Back and Retry");
}
'''

CONTROLLER = r'''
#include "store.h"
#include "probe.h"
#include <stdio.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
typedef int Tb2NativeIO;
typedef struct{Tb2RecordTask* record_task;int result;atomic_bool finished;} ProbeApp;
static unsigned spi_calls, closed;
static Tb2WorkflowIO filesystem(ProbeApp*a,Tb2NativeIO*n){(void)a;(void)n;return (Tb2WorkflowIO){0};}
static void spi_waiting(void*c,bool b){(void)c;(void)b;}
static int run_spi(ProbeApp*a,Tb2SpiRequest*r){(void)a;spi_calls++;assert(r->action==Tb2SpiHeaders);assert(!r->operation&&!r->receipt&&!r->lease&&!r->path&&!r->expected_uid);assert(r->headers->slots[0].status==Tb2HeaderNotRead);return 0;}
static int record_result(int rc){return rc;}
static int store_access(ProbeApp*a,Tb2WorkflowIO*i,Tb2StoreRequest*r){(void)a;(void)i;(void)r;assert(0);return 1;}
static unsigned furi_hal_rtc_get_timestamp(void){assert(0);return 0;}
static void close_controls(ProbeApp*a){(void)a;closed++;}
/* WORKER */
int main(void){
    Tb2RecordTask task={.kind=Tb2RecordTaskFirmwareHeaders};
    ProbeApp app={.record_task=&task};
    memset(&task.headers,0xaa,sizeof(task.headers));
    assert(record_task_worker(&app)==0&&spi_calls==1&&closed==1&&atomic_load(&app.finished));
    assert(task.kind==Tb2RecordTaskFirmwareHeaders&&!app.result);
    assert(sizeof(Tb2ImportDraft)>=sizeof(Tb2SlotHeaders));
    puts("PASS: controller bypasses store/core and passes no job, file, UID or receipt binding");
}
'''


def main():
    worker = function((ROOT / "src/app_record_tasks.c").read_text(), "record_task_worker")
    with tempfile.TemporaryDirectory() as directory:
        for name, content in [("spi", HARNESS), ("controller", CONTROLLER.replace("/* WORKER */", worker))]:
            source = Path(directory) / f"{name}.c"
            binary = Path(directory) / name
            source.write_text(content)
            command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src"), str(source)]
            if name == "spi":
                command.append(str(ROOT / "src/spi_headers.c"))
            subprocess.run(command + ["-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=10)
    boxes = (ROOT / "src/boxes.c").read_text()
    assert 'add(b, "Identify box", BoxIdentify);\n        add(b, "Identify Firmware", BoxIdentifyFirmware);' in boxes
    backend = (ROOT / "src/spi_backend.c").read_text()
    assert "request->action == Tb2SpiHeaders" in backend
    assert "tb2_spi_headers_run(&transport, request)" in backend
    print("PASS: menu order and dedicated SPI dispatch")


if __name__ == "__main__":
    main()
