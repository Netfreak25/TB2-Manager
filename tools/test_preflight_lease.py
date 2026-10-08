"""Compile actual review/lease functions against an exclusive-open storage fake.

Run with Python and a host C compiler (CC or cc); --baseline-ref verifies that
the specified old review implementation fails the same behavioral regression.
No device data or firmware image is required.
"""

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    """Extract an unchanged C function including its static declaration."""
    start = source.index("static ", source.rfind("\n}", 0, source.index(name + "(")))
    body = source.index("{", source.index(name + "(", start))
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define TB2_IMAGE_SIZE (16U * 1024U * 1024U)
#define TB2_PROBE_IO_ERROR 1
#define Tb2FileRead 0
typedef struct { const char* path; bool open; uint64_t size; unsigned pos; } File;
static File image = {"/ext/image.bin", true, TB2_IMAGE_SIZE, 123};
static File other = {"/ext/other.bin", false, TB2_IMAGE_SIZE, 0};
static unsigned opens, closes, duplicates;
static void* file_open(void* ctx, const char* path, int mode) {
    (void)ctx; (void)mode; opens++;
    File* f = !strcmp(path,image.path) ? &image : !strcmp(path,other.path) ? &other : NULL;
    if(f && f->open) { duplicates++; return NULL; } /* SDK would wait forever. */
    if(f) f->open=true;
    return f;
}
static bool file_close(void* ctx, void* file) {
    (void)ctx; File* f=file; assert(f->open); f->open=false; closes++; return true;
}
static uint64_t file_size(void* ctx, void* file) {
    (void)ctx; File* f=file; assert(f->open); return f->size;
}
static bool file_seek(void* ctx, void* file, uint32_t pos) {
    (void)ctx; File* f=file; assert(f->open); f->pos=pos; return true;
}
typedef struct {
    void* context;
    void* (*open)(void*,const char*,int);
    bool (*close)(void*,void*);
    uint64_t (*size)(void*,void*);
    bool (*seek)(void*,void*,uint32_t);
    void** image_lease;
} Tb2WorkflowIO;
typedef struct { char image[256],source[256],created[15]; int state,phase,result,kind; } Tb2Operation;
static inline bool tb2_operation_pure(int kind) { return kind==6 || kind==7; }
typedef struct {
    Tb2WorkflowIO* filesystem; Tb2Operation* operation; bool historical;
    char path[256],error[224],warning[224],directory[128];
} Tb2SetupRequest;
typedef struct { Tb2SetupRequest* request; char buffer[1800]; } Review;
static void review_text(Review* r) { (void)r; }
typedef struct { Tb2WorkflowIO* io; void** lease; const char* path; } Request;
typedef struct { Request* r; void* file; } Spi;
static int failure(Spi* s,int rc,const char* text) { (void)s; (void)text; return rc; }
typedef struct { void* file_lease; char warning[224]; } ProbeApp;
typedef int Tb2NativeIO;
#define SD_RETRY "SD failure"
#define strlcpy(dst,src,size) snprintf(dst,size,"%s",src)
static Tb2WorkflowIO fs;
static Tb2WorkflowIO filesystem(ProbeApp* app, Tb2NativeIO* native) {
    (void)app; (void)native; return fs;
}
/* FUNCTIONS */
int main(void) {
    ProbeApp app={.file_lease=&image};
    fs=(Tb2WorkflowIO){NULL,file_open,file_close,file_size,file_seek,&app.file_lease};
    Tb2Operation op={.image="/ext/image.bin",.source="/ext/image.bin",.created="20260929120000"};
    Tb2SetupRequest q={.filesystem=&fs,.operation=&op,.path="/ext/image.bin"};
    Review r={.request=&q};
    for(unsigned i=0;i<3;i++) review_operation(&r);
    if(duplicates) { puts("FAIL: details reopened the held image (SDK deadlock)"); return 1; }
    assert(opens==0 && closes==0 && image.pos==123 && app.file_lease==&image);
    assert(strstr(r.buffer,"Image present"));
    op.kind=7; review_operation(&r);
    assert(!strstr(r.buffer,"Package:") && !strstr(r.buffer,"Backups:"));
    /* Flash takes ownership of the same handle and rewinds it without open. */
    Request request={&fs,&app.file_lease,op.image}; Spi spi={.r=&request};
    assert(open_source(&spi)==0 && spi.file==&image && !app.file_lease);
    assert(opens==0 && image.pos==0); assert(close_file(&spi));
    /* Historical details without a lease use a short-lived handle. */
    q.historical=true; review_operation(&r);
    assert(opens==1 && closes==2 && !image.open);
    image.size=1; review_operation(&r); assert(strstr(r.buffer,"Image missing or incomplete"));
    strcpy(op.image,"/ext/missing.bin"); review_operation(&r);
    assert(strstr(r.buffer,"Image missing or incomplete"));
    /* A lease for another selected image is not proof for this operation. */
    q.historical=false; image.open=true; image.size=TB2_IMAGE_SIZE; app.file_lease=&image;
    strcpy(op.image,other.path); unsigned before=opens; review_operation(&r);
    assert(opens==before+1 && !other.open && image.open && app.file_lease==&image);
    /* Abandoning the operation closes the resident lease exactly once. */
    before=closes; release_lease(&app); release_lease(&app);
    assert(closes==before+1 && !app.file_lease && !image.open && duplicates==0);
    puts("PASS: held details, repeat, flash handoff, historical, invalid/missing, foreign path, cancel");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref")
    args = parser.parse_args()
    review = (ROOT / "src/review_ui.c").read_text(encoding="utf-8")
    if args.baseline_ref:
        review = subprocess.check_output(
            ["git", "show", f"{args.baseline_ref}:src/review_ui.c"], cwd=ROOT, text=True
        )
    spi = (ROOT / "src/spi.c").read_text(encoding="utf-8")
    hardware = (ROOT / "src/app_hardware.c").read_text(encoding="utf-8")
    functions = "\n".join([
        function(review, "review_operation"), function(spi, "close_file"),
        function(spi, "open_source"), function(hardware, "release_lease"),
    ])
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "regression.c"
        binary = Path(tmp) / "regression"
        source.write_text(HARNESS.replace("/* FUNCTIONS */", functions), encoding="utf-8")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                        "-Werror", str(source), "-o", str(binary)], check=True)
        result = subprocess.run([str(binary)], check=False, timeout=10)
        if args.baseline_ref:
            if result.returncode != 1:
                raise SystemExit("Baseline did not reproduce the expected duplicate open")
            print("PASS: baseline reproduces duplicate-open regression")
        elif result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
