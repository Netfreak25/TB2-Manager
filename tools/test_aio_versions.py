"""Focused production SPI comparison/AIO lease regression; synthetic bytes only."""
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
extern unsigned hashes;
typedef struct { unsigned unused; } mbedtls_sha256_context;
static inline void mbedtls_sha256_init(mbedtls_sha256_context*c){(void)c;}
static inline void mbedtls_sha256_free(mbedtls_sha256_context*c){(void)c;}
static inline int mbedtls_sha256_starts(mbedtls_sha256_context*c,int n){(void)c;(void)n;hashes++;return 0;}
static inline int mbedtls_sha256_update(mbedtls_sha256_context*c,const unsigned char*b,size_t n){(void)c;(void)b;(void)n;return 0;}
static inline int mbedtls_sha256_finish(mbedtls_sha256_context*c,unsigned char*b){(void)c;memset(b,0,32);return 0;}
'''
HARNESS = r'''
#include "spi.c"
#include <assert.h>
unsigned hashes;
static unsigned opens,closes,reads,erases,writes,now,waits;
static uint32_t position,file_size,difference;
static int mode;
static bool opened,wel;
static void* open_file(void*c,const char*p,Tb2FileMode m){
    (void)c;assert(!strcmp(p,"/modified.bin") && m==Tb2FileRead && !opened);
    opens++;opened=true;position=0;return &position;
}
static bool close_source(void*c,void*f){(void)c;assert(f==&position && opened);opened=false;closes++;return true;}
static uint64_t size_file(void*c,void*f){(void)c;assert(f==&position);return file_size;}
static bool seek_file(void*c,void*f,uint32_t p){(void)c;assert(f==&position);position=p;return true;}
static size_t read_file(void*c,void*f,void*b,size_t n){
    (void)c;assert(f==&position && opened && position+n<=TB2_IMAGE_SIZE);
    if(mode==3 && position+n==TB2_IMAGE_SIZE)return n-1;
    memset(b,0xff,n);position+=n;return n;
}
static bool stop(void*c){(void)c;return (mode==4 && reads==2)||(mode==5 && now>=50);}
static void waiting(void*c,bool active){(void)c;waits+=active?1:2;}
static bool begin(void*c){(void)c;return true;}
static void end(void*c){(void)c;}
static uint32_t tick(void*c){(void)c;return now;}
static void delay(void*c,uint32_t n){(void)c;now+=n;}
static bool transfer(void*c,const uint8_t*t,size_t n,uint8_t*r,size_t z){
    (void)c;
    switch(t[0]) {
    case 0x9f: assert(n==1 && z==3);r[0]=mode==5?0xff:mode==6?0xc2:0xef;r[1]=0x40;r[2]=0x18;break;
    case 0x4b: assert(n==5 && z==8);memset(r,mode==7?2:1,z);break;
    case 0x05: assert(n==1 && z==1);*r=wel?2:0;break;
    case 0x35: case 0x15: case 0x3d: memset(r,0,z);break;
    case 0x06: assert(!z);wel=true;break;
    case 0xc7: assert(wel && !z);wel=false;erases++;break;
    case 0x02: assert(wel && n==260 && !z);wel=false;writes++;break;
    case 0x03: {
        assert(n==4 && z==TB2_SPI_CHUNK);
        uint32_t off=(uint32_t)t[1]<<16|(uint32_t)t[2]<<8|t[3];
        assert(off==reads*TB2_SPI_CHUNK);reads++;
        if(mode==2 && off+z==TB2_IMAGE_SIZE)return false;
        memset(r,0xff,z);
        if(off<=difference && difference<off+z)r[difference-off]=0;
        break;
    }
    default: assert(false);
    }
    return true;
}
int tb2_identity_firmwares(Tb2Reader*r,Tb2FirmwareIdentity*a,Tb2FirmwareIdentity*b){
    (void)r;(void)a;(void)b;assert(false);return 1;
}
static void reset(void){assert(!opened);opens=closes=reads=erases=writes=hashes=now=waits=0;position=0;
    file_size=TB2_IMAGE_SIZE;difference=UINT32_MAX;mode=0;wel=false;}
int main(void){
    Tb2WorkflowIO io={.open=open_file,.close=close_source,.read=read_file,.size=size_file,.seek=seek_file,.cancelled=stop};
    Tb2SpiTransport bus={.begin=begin,.end=end,.transfer=transfer,.milliseconds=tick,.delay=delay};
    Tb2SpiReceipt receipt={0};Tb2SpiResult result;
    Tb2SpiRequest r={.io=&io,.path="/modified.bin",.action=Tb2SpiCompare,.receipt=&receipt,.result=&result,.waiting=waiting};
    reset();assert(!tb2_spi_run(&bus,&r));assert(!result.different && reads==TB2_IMAGE_SIZE/TB2_SPI_CHUNK);
    assert(opens==1 && closes==1 && !hashes && !erases && !writes && !receipt.flags && waits==3);
    for(unsigned i=0;i<2;i++){reset();difference=i?TB2_IMAGE_SIZE-1:0;
        assert(!tb2_spi_run(&bus,&r) && result.different);assert(reads==TB2_IMAGE_SIZE/TB2_SPI_CHUNK && !hashes);}
    for(int m=2;m<=6;m++){reset();mode=m;difference=0;assert(tb2_spi_run(&bus,&r));
        assert(!opened && !erases && !writes && !hashes && opens==closes);}
    reset();file_size--;assert(tb2_spi_run(&bus,&r));assert(!reads && opens==closes);
    reset();assert(!tb2_spi_run(&bus,&r) && !result.different); /* Retry clears old result. */
    reset();Tb2Operation op={.kind=Tb2OperationAio};void* lease=NULL;
    r.operation=&op;r.lease=&lease;r.action=Tb2SpiFlash;
    receipt.flags=Tb2SpiBound|Tb2SpiFileChecked|Tb2SpiDigestBound;memset(receipt.uid,1,8);
    assert(!tb2_spi_run(&bus,&r));assert(opened && lease && closes==0 && erases==1 && hashes==3);
    assert(receipt.flags & Tb2SpiFlashVerified);
    reads=0;hashes=0;assert(!tb2_spi_run(&bus,&r));assert(opens==1 && closes==0 && erases==2 && hashes==2);
    reads=0;mode=7;assert(tb2_spi_run(&bus,&r)==Tb2SpiDifferentChip);assert(!lease && !opened && closes==1 && erases==2);
    reset();mode=0;op.kind=Tb2OperationPureFlash;assert(!tb2_spi_run(&bus,&r));assert(!lease && !opened && opens==closes);
    puts("PASS: chip compare full read, mismatch, errors/Back/Retry; AIO lease reuse, UID rejection, pure-flash close");
}
'''

def main():
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / 'mbedtls').mkdir()
        (directory / 'mbedtls/sha256.h').write_text(SHA)
        source = directory / 'test.c'
        source.write_text(HARNESS)
        binary = directory / 'test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(directory), '-I', str(ROOT / 'src'), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)

if __name__ == '__main__':
    main()
