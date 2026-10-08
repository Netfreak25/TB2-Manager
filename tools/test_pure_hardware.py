"""Exercise production hardware coordination with counted module boundaries.

No private images, SDK, or hardware required. Run using Python 3 and CC/cc.
The SPI fake supplies receipts, not a simulation of flash contents. The existing
lease regression separately exercises real source-handle ownership.
"""

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

from test_preflight_lease import function

ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include "store.h"
#include "probe.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SD_RETRY "SD access failed"
#define strlcpy(dst,src,n) snprintf(dst,n,"%s",src)
enum { FlipperApplicationPreloadStatusInvalidFile=1,
       FlipperApplicationPreloadStatusNotEnoughMemory=2 };
typedef int Tb2NativeIO;
typedef struct {
    Tb2Operation operation;
    Tb2SpiAction spi_action;
    Tb2SpiReceipt chip;
    Tb2InputKey input_key, donor_key;
    Tb2RecordTask* record_task;
    Tb2WorkflowResult flow;
    bool known_uid, key_from_file, identification_worker, metadata_ready, abort;
    bool lease;
    void* file_lease;
    unsigned hardware_options;
    uint8_t expected_uid[8];
    char box_id[33], version_id[33], selected_version[33], original_version[33];
    char box_alias[49], key_path[256], run_dir[128], error[224], warning[224];
    int result;
    atomic_bool finished;
} ProbeApp;
static unsigned record_calls, spi_calls, archive_calls, log_closed, saves, events;
static bool stop_spi, fail_spi;
static Tb2SpiAction last_spi;
static Tb2WorkflowIO filesystem(ProbeApp* a, Tb2NativeIO* n) {
    (void)a; (void)n; return (Tb2WorkflowIO){0};
}
static void furi_string_reset(char* p) { *p=0; }
static void ui_status(ProbeApp* a, const char* s, bool error) {
    if(error) snprintf(a->error,sizeof(a->error),"%s",s);
}
static void log_event(ProbeApp* a,const char* stage,int rc,const char* detail) {
    (void)a; assert(stage && rc && detail); events++;
}
static Tb2RecordResult store_access(ProbeApp* a,Tb2WorkflowIO* fs,Tb2StoreRequest* r) {
    (void)a; (void)fs; record_calls++;
    if(r->action==Tb2StoreFlashReady) archive_calls++;
    if(r->action==Tb2StoreDescribe) strcpy(r->alias,"Selected box");
    return Tb2RecordOk;
}
static int record_result(Tb2RecordResult r) { return r; }
static int record_restore_plan(ProbeApp* a,Tb2WorkflowIO* fs,bool create) {
    (void)a;(void)fs;(void)create; record_calls++; return 0;
}
static void run_worker_ui(ProbeApp* a,Tb2WorkflowAction action) {
    (void)a;(void)action; record_calls++;
}
static bool invoke_setup(ProbeApp* a,Tb2SetupRequest* r) {
    (void)a;record_calls++;r->action=Tb2SetupActionBoxSelected;
    strcpy(r->box_id,"selected");return true;
}
static void run_record_task(ProbeApp* a) { (void)a;record_calls++; }
static void clear_record_task(ProbeApp* a) { a->record_task=NULL; }
static bool prepare_run(ProbeApp* a,Tb2WorkflowIO* fs) { (void)a;(void)fs;return true; }
static bool operation_access(ProbeApp* a,Tb2WorkflowIO* fs,Tb2OperationAccess access) {
    (void)fs;(void)access;a->operation.sequence++;saves++;return true;
}
static int record_bind(ProbeApp* a,Tb2WorkflowIO* fs) { (void)a;(void)fs;record_calls++;return 0; }
static int archive_before_flash(ProbeApp* a,Tb2WorkflowIO* fs) {
    (void)a;(void)fs;archive_calls++;return 0;
}
static int archive_verified_source(ProbeApp* a,Tb2WorkflowIO* fs) {
    (void)a;(void)fs;archive_calls++;return 0;
}
static int export_and_flash(ProbeApp* a,Tb2WorkflowIO* fs) {
    (void)a;(void)fs;archive_calls++;return 0;
}
static int record_publish(ProbeApp* a,Tb2WorkflowIO* fs,const char* path,
                          const uint8_t* digest,Tb2WorkshopSlot slot,bool checked) {
    (void)a;(void)fs;(void)path;(void)digest;(void)slot;(void)checked;record_calls++;return 0;
}
static bool close_controls(ProbeApp* a) { return a->abort; }
static void close_worker_log(ProbeApp* a) { (void)a;log_closed++; }
static void release_lease(ProbeApp* a) { a->lease=false; a->file_lease=NULL; }
static void save_status(ProbeApp* a,Tb2UiState state) { (void)a;(void)state; }
static int spi_phase(ProbeApp* a,Tb2WorkflowIO* fs,Tb2SpiAction action) {
    (void)fs;spi_calls++;last_spi=action;
    if(stop_spi) return TB2_PROBE_CANCELLED;
    if(fail_spi) return TB2_PROBE_IO_ERROR;
    Tb2Operation* op=&a->operation;
    if(action==Tb2SpiRead) op->dump.flags=Tb2SpiBound|Tb2SpiOwned|Tb2SpiDumpSaved;
    if(action==Tb2SpiVerifyRead) {
        op->dump.flags|=Tb2SpiDumpVerified|Tb2SpiDigestBound;
        op->phase=Tb2PhaseSourceVerify;
    }
    if(action==Tb2SpiPreflight) {
        op->flash.flags=Tb2SpiBound|Tb2SpiFileChecked|Tb2SpiDigestBound;a->lease=true;
    }
    if(action==Tb2SpiFlash || action==Tb2SpiVerifyFlash) {
        assert(op->approved);
        op->flash.flags|=Tb2SpiEraseStarted|Tb2SpiWriteDone|Tb2SpiFlashVerified;
        op->phase=Tb2PhaseFlashVerify;a->lease=false;
    }
    return 0;
}
/* FUNCTIONS */

static void reset(ProbeApp* a,Tb2OperationKind kind) {
    memset(a,0,sizeof(*a));a->operation.kind=kind;a->operation.format=3;
    a->operation.state=Tb2UiPrepared;
    a->operation.phase=tb2_operation_flash(kind)?Tb2PhaseFlashPrepare:Tb2PhaseSource;
    strcpy(a->operation.source,"/ext/test.bin");
    strcpy(a->operation.image,"/ext/test.bin");
    strcpy(a->operation.created,"20260929123456");
    strcpy(a->box_id,"stale-box");strcpy(a->version_id,"stale-version");
    strcpy(a->selected_version,"stale-version");strcpy(a->box_alias,"Stale alias");
    a->known_uid=true;memset(a->expected_uid,1,8);
    memset(&a->input_key,1,sizeof(a->input_key));strcpy(a->key_path,"private-key");
    record_calls=spi_calls=archive_calls=saves=log_closed=0;stop_spi=fail_spi=false;
}
static void step(ProbeApp* a,Tb2SetupAction action) {
    assert(choose_record(a,true,a->operation.sequence!=0));
    a->spi_action=spi_action(a,action);
    hardware_worker(a);
    assert(atomic_load(&a->finished) && log_closed);
    finish_hardware(a);
}
int main(void) {
    ProbeApp a;
    assert(operation_kind(Tb2SetupActionPureDump)==Tb2OperationPureDump);
    assert(operation_kind(Tb2SetupActionPureFlash)==Tb2OperationPureFlash);
    assert(operation_kind(Tb2SetupActionDump)==Tb2OperationDump);
    assert(operation_kind(Tb2SetupActionFlash)==Tb2OperationFlash);
    reset(&a,Tb2OperationPureDump);step(&a,Tb2SetupActionRead);
    if(record_calls || archive_calls || spi_calls!=1) {
        puts("FAIL: pure read invoked record/archive processing");return 1;
    }
    assert(a.operation.dump.flags & Tb2SpiDumpSaved);
    assert(!(a.operation.dump.flags & Tb2SpiDumpVerified));
    assert(a.operation.phase==Tb2PhaseSourceVerify && a.operation.state==Tb2UiPrepared);
    assert(!a.box_id[0] && !a.version_id[0] && !a.selected_version[0] && !a.box_alias[0]);
    assert(!a.known_uid && !a.key_path[0]);
    Tb2InputKey empty={0};assert(!memcmp(&empty,&a.input_key,sizeof(empty)));
    step(&a,Tb2SetupActionVerifyRead);
    assert(!record_calls && !archive_calls && spi_calls==2);
    assert(a.operation.state==Tb2UiComplete && a.operation.phase==Tb2PhaseComplete);
    step(&a,Tb2SetupActionVerifyRead);assert(last_spi==Tb2SpiVerifyRead && !archive_calls);
    reset(&a,Tb2OperationPureFlash);step(&a,Tb2SetupActionPureFlash);
    assert(a.operation.phase==Tb2PhaseFlashPrepare && a.lease);
    assert(!record_calls && !archive_calls && last_spi==Tb2SpiPreflight);
    a.operation.approved=true;step(&a,Tb2SetupActionProgram);
    assert(a.operation.state==Tb2UiComplete && last_spi==Tb2SpiFlash);
    assert(!record_calls && !archive_calls);
    step(&a,Tb2SetupActionVerifyFlash);assert(last_spi==Tb2SpiVerifyFlash && !record_calls);
    /* Restart/Retry preserves the persisted kind, not the previously selected box. */
    for(int kind=Tb2OperationPureDump;kind<=Tb2OperationPureFlash;kind++) {
        reset(&a,kind);a.operation.sequence=3;stop_spi=true;
        step(&a,Tb2SetupActionRetryOperation);assert(a.operation.state==Tb2UiPaused);
        stop_spi=false;fail_spi=true;step(&a,Tb2SetupActionRetryOperation);
        assert(a.operation.state==Tb2UiFailed);
        fail_spi=false;step(&a,Tb2SetupActionRetryOperation);
        assert(!record_calls && !archive_calls && spi_calls==3);
        a.abort=true;step(&a,Tb2SetupActionRetryOperation);assert(a.operation.state==Tb2UiAborted);
    }
    reset(&a,Tb2OperationDump);step(&a,Tb2SetupActionVerifyRead);
    assert(record_calls && archive_calls==1 && a.operation.phase==Tb2PhaseArchiveSource);
    reset(&a,Tb2OperationFlash);a.operation.approved=true;step(&a,Tb2SetupActionProgram);
    assert(record_calls && archive_calls==1);
    reset(&a,Tb2OperationAio);step(&a,Tb2SetupActionVerifyRead);
    assert(record_calls && archive_calls==1 && a.operation.phase==Tb2PhaseArchiveSource);
    reset(&a,Tb2OperationAio);a.operation.approved=true;step(&a,Tb2SetupActionProgram);
    assert(record_calls && last_spi==Tb2SpiFlash);
    reset(&a,Tb2OperationAio);a.operation.approved=true;
    a.operation.state=Tb2UiComplete;a.operation.phase=Tb2PhaseComplete;
    a.operation.flash.flags=Tb2SpiBound|Tb2SpiFlashVerified;
    a.file_lease=&a;step(&a,Tb2SetupActionProgram);
    assert(!archive_calls && last_spi==Tb2SpiFlash);
    a.file_lease=NULL;step(&a,Tb2SetupActionProgram);
    assert(archive_calls==1); /* Restart/lost lease must revalidate archive. */
    assert(!module_error(&a,"module_preload",0,"OK"));
    assert(module_error(&a,"module_preload",2,"Not enough memory"));
    assert(strstr(a.error,"Not enough memory"));
    module_error(&a,"module_preload",1,"Invalid file");assert(strstr(a.error,"missing"));
    module_error(&a,"module_descriptor",1,"tb2_spi");assert(strstr(a.error,"incompatible"));
    assert(events==3);
    puts("PASS: production routes, raw read/verify/flash, retries, stop, abort, stale selection, box/AIO, loader errors");
}
'''

CODEC = r'''
#include "operation.c"
#include <assert.h>
typedef struct { uint8_t data[8192]; size_t pos,size; bool open; } File;
static File files[2];
static int index_of(const char* path) { return strstr(path,"operation.bin")?1:0; }
static void* open_file(void* c,const char* path,Tb2FileMode mode) {
    (void)c;File* f=&files[index_of(path)];assert(!f->open);
    if(mode==Tb2FileNew && f->size) return NULL;
    if(mode==Tb2FileRead && !f->size) return NULL;
    f->open=true;f->pos=0;return f;
}
static bool close_file(void* c,void* h) { (void)c;File* f=h;assert(f->open);f->open=false;return true; }
static size_t read_file(void* c,void* h,void* b,size_t n) {
    (void)c;File* f=h;if(n>f->size-f->pos)n=f->size-f->pos;
    memcpy(b,f->data+f->pos,n);f->pos+=n;return n;
}
static size_t write_file(void* c,void* h,const void* b,size_t n) {
    (void)c;File* f=h;assert(f->pos+n<=sizeof(f->data));
    memcpy(f->data+f->pos,b,n);f->pos+=n;if(f->pos>f->size)f->size=f->pos;return n;
}
static uint64_t size_file(void* c,void* h) { (void)c;return ((File*)h)->size; }
static bool seek_file(void* c,void* h,uint32_t n) { (void)c;((File*)h)->pos=n;return true; }
static bool sync_file(void* c,void* h) { (void)c;(void)h;return true; }
static bool truncate_file(void* c,void* h) { (void)c;File* f=h;f->size=f->pos;return true; }
static int exists_file(void* c,const char* path) { (void)c;return files[index_of(path)].size!=0; }
int main(void) {
    Tb2WorkflowIO io={.open=open_file,.close=close_file,.read=read_file,.write=write_file,
        .size=size_file,.seek=seek_file,.sync=sync_file,.truncate=truncate_file,.exists=exists_file};
    const char* dir="/ext/test-job";
    for(int kind=Tb2OperationPureDump;kind<=Tb2OperationPureFlash;kind++) {
        memset(files,0,sizeof(files));
        Tb2Operation op={.kind=kind,.state=Tb2UiPrepared}, loaded;
        strcpy(op.source,"/ext/test.bin");strcpy(op.image,"/ext/test.bin");
        strcpy(op.created,"20260929123456");
        op.phase=tb2_operation_flash(kind)?Tb2PhaseFlashPrepare:Tb2PhaseSource;
        assert(tb2_operation_create(&io,dir,&op));
        assert(tb2_operation_load(&io,dir,&loaded));
        assert(loaded.kind==op.kind && loaded.format==3 && loaded.sequence==1);
        op.state=Tb2UiPaused;assert(tb2_operation_save(&io,dir,&op,false));
        assert(tb2_operation_load(&io,dir,&loaded) && loaded.kind==op.kind);
        op.state=Tb2UiComplete;op.phase=Tb2PhaseComplete;
        assert(!tb2_operation_save(&io,dir,&op,false)); /* No false success. */
        if(kind==Tb2OperationPureDump)
            op.dump.flags=Tb2SpiBound|Tb2SpiOwned|Tb2SpiDumpSaved|Tb2SpiDigestBound|Tb2SpiDumpVerified;
        else
            op.flash.flags=Tb2SpiBound|Tb2SpiDigestBound|Tb2SpiFileChecked|Tb2SpiEraseStarted|
                Tb2SpiWriteDone|Tb2SpiFlashVerified;
        assert(tb2_operation_save(&io,dir,&op,false));
        assert(tb2_operation_load(&io,dir,&loaded) && loaded.state==Tb2UiComplete);
        op.phase=Tb2PhaseArchiveSource;op.state=Tb2UiPrepared;assert(!state_valid(&op));
    }
    /* Existing v1/v2/v3 descriptors and journals retain their kind and meaning. */
    for(unsigned format=1;format<=3;format++) {
        memset(files,0,sizeof(files));
        Tb2Operation op={.kind=Tb2OperationFlash,.format=format,.state=Tb2UiPaused,
            .phase=Tb2PhaseFlashPrepare,.sequence=1},loaded;
        strcpy(op.source,"/ext/old.bin");strcpy(op.image,op.source);
        strcpy(op.created,"20260929123456");encode_info(&op,dir,files[0].data);
        files[0].size=TB2_OPERATION_SPEC_SIZE;
        op.descriptor_crc=get32(files[0].data+TB2_OPERATION_SPEC_SIZE-4);
        encode_state(&op,files[1].data);files[1].size=TB2_OPERATION_RECORD_SIZE;
        assert(tb2_operation_load(&io,dir,&loaded));
        assert(loaded.kind==Tb2OperationFlash && loaded.format==format && !tb2_operation_pure(loaded.kind));
    }
    puts("PASS: real operation persistence, pure round-trip, verified-only completion, legacy v1/v2/v3");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", help="Reproduce record calls in the old hardware worker")
    args = parser.parse_args()
    app = (ROOT / "src/app.c").read_text(encoding="utf-8")
    hardware = (ROOT / "src/app_hardware.c").read_text(encoding="utf-8")
    if args.baseline_ref:
        hardware = subprocess.check_output(
            ["git", "show", f"{args.baseline_ref}:src/app_hardware.c"], cwd=ROOT, text=True)
    functions = "\n".join([
        *(function(app, name) for name in
          ("choose_record", "operation_kind", "spi_action", "module_error")),
        *(function(hardware, name) for name in ("hardware_worker", "finish_hardware")),
    ])
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "pure.c"
        binary = Path(tmp) / "pure"
        source.write_text(HARNESS.replace("/* FUNCTIONS */", functions), encoding="utf-8")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", "-I", str(ROOT / "src"), str(source), "-o", str(binary)],
                       check=True)
        result = subprocess.run([str(binary)], check=False, timeout=10)
        if args.baseline_ref:
            if result.returncode != 1:
                raise SystemExit("Baseline did not reproduce record calls")
            print("PASS: baseline reproduces unwanted record processing")
            return
        result.check_returncode()
        source.write_text(CODEC, encoding="utf-8")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", "-ffunction-sections", "-Wl,--gc-sections",
                        "-I", str(ROOT / "src"), str(source), str(ROOT / "src/job.c"),
                        "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    main()
