"""Exercise the box-Flash archive boundary and low-memory identity dispatch."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from test_core_clock import function

ROOT = Path(__file__).resolve().parents[1]
BASELINE = 'aea33cb'  # Last revision before this archive-routing fix.
FAKE = r'''
#include "store.h"
#include "probe.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    Tb2Operation operation;
    Tb2SpiResult spi_result;
    Tb2ImageIdentity identity;
    bool known_uid;
    uint8_t expected_uid[8];
    char run_dir[128], artifact_directory[TB2_JOB_PATH_MAX];
    void* file_lease;
} ProbeApp;
static unsigned closed, inspected, hardware, publications;
static bool backup_exists=true;
static void spi_waiting(void*c,bool w){(void)c;(void)w;}
static int record_result(Tb2RecordResult rc){return (int)rc;}
static void release_lease(ProbeApp*a){if(a->file_lease){closed++;a->file_lease=NULL;}}
static int run_spi(ProbeApp*a,Tb2SpiRequest*r){
    if(r->action==Tb2SpiInspectFile){
        assert(!a->file_lease);
        inspected++;assert(r->identity==&a->identity);
        assert(r->path&&r->directory&&strstr(r->directory,"-artifacts"));
    }else{assert(r->action==Tb2SpiFirmware);hardware++;}
    return 0;
}
static Tb2RecordResult store_access(ProbeApp*a,Tb2WorkflowIO*io,Tb2StoreRequest*r){
    (void)io;assert(!a->file_lease); /* Same BIN can be a retained original backup. */
    assert(r->action==Tb2StoreBackup||r->action==Tb2StoreFlashReady);
    r->found=backup_exists;return Tb2RecordOk;
}
/* INSPECT */
static int record_publish(ProbeApp*a,Tb2WorkflowIO*io,const char*p,const uint8_t*d,Tb2WorkshopSlot s,bool c){
    (void)d;(void)c;publications++;
    return INSPECT_CALL;
}
/* ARCHIVE */
int main(int argc,char**argv){
    ProbeApp app={0};Tb2WorkflowIO io={0};
    strcpy(app.run_dir,"/ext/jobs/test");strcpy(app.operation.image,"/ext/box.bin");
    if(argc>1&&!strcmp(argv[1],"identity")){
        assert(!record_publish(&app,&io,app.operation.image,NULL,Tb2WorkshopTarget,false));
        assert(inspected==1);puts("PASS: identity/artifact scan uses small SPI module, never Core");
        return 0;
    }
    for(unsigned mode=0;mode<3;mode++){
        closed=inspected=hardware=publications=0;
        app.file_lease=&app;backup_exists=mode!=1;
        app.operation.flash.flags=mode==2?Tb2SpiEraseStarted:0;
        assert(!archive_before_flash(&app,&io));
        assert(closed==1&&!app.file_lease);
        assert(inspected==(mode==2?0:mode==1?2:1));
        assert(hardware==(mode==2?0:mode==1?2:1));
    }
    puts("PASS: lease closed before backup/archive access; retained/missing backup and partial-flash retry");
}
'''


def main():
    before = '--before' in sys.argv
    def source(name):
        if before:
            return subprocess.check_output(['git', 'show', f'{BASELINE}:src/{name}'], cwd=ROOT, text=True)
        return (ROOT / 'src' / name).read_text()
    inspect = function(source('app_records.c'), 'inspect_identity_file')
    call = 'inspect_identity_file(a,io,p,s==Tb2WorkshopTarget?"target":"backup"' + (',false)' if before else ')')
    if before:
        inspect = 'static int core_inspect(ProbeApp*a,Tb2BackendInspect*r){(void)a;(void)r;return TB2_PROBE_IO_ERROR;}\n' + inspect
    program = FAKE.replace('/* INSPECT */', inspect).replace('INSPECT_CALL', call)
    program = program.replace('/* ARCHIVE */', function(source('app_hardware.c'), 'archive_before_flash'))
    if before:
        program = '#include "backend.h"\n' + program
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'archive.c'
        binary = Path(tmp) / 'archive'
        path.write_text(program)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                        '-Wno-unused-function', '-Werror', '-I', str(ROOT / 'src'),
                        str(path), '-o', str(binary)], check=True)
        for case in ['identity', 'archive']:
            result = subprocess.run([str(binary), case], timeout=10, capture_output=True, text=True, check=False)
            if before:
                assert result.returncode != 0, 'Previous path must reproduce the regression'
                print(f'EXPECTED FAIL (previous {case} path): {result.stderr.strip()}')
            else:
                if result.returncode:
                    raise RuntimeError(result.stderr)
                print(result.stdout.strip())


if __name__ == '__main__':
    main()
