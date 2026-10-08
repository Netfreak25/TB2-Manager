"""Execute actual name proposal, display details and rename invariants with fake metadata IO."""
import os
import subprocess
import tempfile
from pathlib import Path

from test_preflight_lease import function

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "record_tasks.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VERSION_PAYLOAD TB2_VERSION_PAYLOAD_SIZE
static Tb2BoxVersion saved,pending;
static Tb2Edition edition;
static int edition_result;
static unsigned writes;
Tb2RecordResult tb2_version_load(Tb2WorkflowIO*i,const char*b,const char*v,Tb2BoxVersion*out){(void)i;(void)b;(void)v;*out=saved;return 0;}
Tb2RecordResult tb2_edition_load(Tb2WorkflowIO*i,const char*b,const char*v,Tb2Edition*out){(void)i;(void)b;(void)v;*out=edition;return edition_result;}
Tb2RecordResult tb2_version_image_path(Tb2WorkflowIO*i,const char*b,const char*v,const Tb2ObjectRef*o,char p[TB2_JOB_PATH_MAX]){(void)i;(void)b;(void)v;(void)o;strcpy(p,"/unchanged.bin");return 0;}
Tb2RecordResult tb2_originals(Tb2WorkflowIO*i,const char*b,const Tb2FirmwareIdentity*f,Tb2Originals*out){(void)i;(void)b;(void)f;memset(out,0,sizeof(*out));return 0;}
static bool entry_path(char*p,const char*b,const char*v,const char*t){(void)b;(void)v;(void)t;strcpy(p,"/metadata");return true;}
static bool version_codec(Tb2BoxVersion*v,uint8_t*b,bool write){(void)b;assert(write);pending=*v;return true;}
Tb2RecordResult tb2_box_load(Tb2WorkflowIO*i,const char*b,Tb2BoxRecord*out){(void)i;(void)b;(void)out;return 0;}
Tb2RecordResult tb2_record_write(Tb2WorkflowIO*i,const char*p,Tb2RecordKind k,const char*b,const void*data,size_t n,uint32_t*g){
 (void)i;(void)p;(void)b;(void)data;assert(k==Tb2RecordVersion && n==VERSION_PAYLOAD);++*g;pending.generation=*g;saved=pending;writes++;return 0;}
static int exists(void*c,const char*p){(void)c;assert(!strcmp(p,"/unchanged.bin"));return 1;}
/* FUNCTIONS */
Tb2RecordResult tb2_version_rename(Tb2WorkflowIO*i,Tb2BoxVersion*v){
 if(!v->generation || !v->name[0] || !memchr(v->name,0,sizeof(v->name)))return Tb2RecordCorrupt;
 return version_save(i,v,true);
}
int main(void){
 Tb2WorkflowIO io={.exists=exists};Tb2BoxRecord box={0};strcpy(box.alias,"Blue");
 Tb2RecordTask task={.kind=Tb2RecordTaskRenamePrepare};
 strcpy(saved.name,"old-name.bin");strcpy(saved.id,"version");saved.generation=1;saved.flags=Tb2VersionProtected;
 edition.primary.known=edition.secondary.known=true;edition.kind=Tb2ImageModified;edition.revision=2;
 strcpy(edition.primary.version,"1.6.9+17");strcpy(edition.secondary.version,"1.6.28+3");
 assert(!version_action(&io,&task,&box));assert(!strcmp(task.path,"Blue_1.6.28_mod_r2.bin") && !writes);
 strcpy(edition.primary.version,"1.10.3+20");assert(!version_action(&io,&task,&box));assert(!strcmp(task.path,"Blue_1.10.3_mod_r2.bin"));
 strcpy(edition.secondary.version,"2.0.65535+4294967295");edition.kind=Tb2ImageOriginal;edition.revision=1;
 assert(!version_action(&io,&task,&box));assert(!strcmp(task.path,"Blue_2.0.65535.bin"));
 edition.primary.known=edition.secondary.known=false;assert(!version_action(&io,&task,&box));assert(!strcmp(task.path,saved.name));
 edition_result=Tb2RecordMissing;saved.firmware.known=true;strcpy(saved.firmware.version,"0.40.8+12");saved.flags|=Tb2VersionOriginal;
 assert(!version_action(&io,&task,&box));assert(!strcmp(task.path,"Blue_0.40.8.bin"));
 Tb2BoxVersion before=saved;task.kind=Tb2RecordTaskRename;strcpy(task.path,"Custom display");
 assert(!version_action(&io,&task,&box));assert(writes==1 && !strcmp(saved.name,"Custom display"));
 memcpy(saved.name,before.name,sizeof(saved.name));saved.generation=before.generation;assert(!memcmp(&saved,&before,sizeof(saved)));
 Tb2BoxVersion changed=saved;strcpy(changed.name,"Another");assert(version_save(&io,&changed,false)==Tb2RecordConflict);
 changed.image.digest[0]=1;assert(tb2_version_rename(&io,&changed)==Tb2RecordConflict && writes==1);
 task.kind=Tb2RecordTaskVersionDetails;assert(!details(&io,&task,&box));assert(strstr(task.report,"Slot A: 0.40.8+12\nSlot B: Unknown"));
 edition_result=0;edition.primary.known=edition.secondary.known=true;assert(!details(&io,&task,&box));
 assert(strstr(task.report,"Slot A: 1.10.3+20\nSlot B: 2.0.65535+4294967295"));
 uint32_t parts[4];strcpy(edition.primary.version,"1.2.3+4294967296");assert(!header_version(&edition.primary,parts));
 puts("PASS: numerical dual-slot names, Original/Modified, revision, unknown/legacy, name-only persistence, both detail slots");
}
'''
def main():
    tasks = (ROOT / 'src/record_tasks.c').read_text()
    records = (ROOT / 'src/records.c').read_text()
    functions = '\n'.join([*(function(records, n) for n in ('immutable_version', 'version_save')),
                           *(function(tasks, n) for n in ('hex', 'details', 'header_version', 'version_action'))])
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'names.c'
        binary = Path(tmp) / 'names'
        source.write_text(HARNESS.replace('/* FUNCTIONS */', functions))
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-ffunction-sections', '-Wl,--gc-sections', '-I', str(ROOT / 'src'),
                        str(source), str(ROOT / 'src/editions.c'), str(ROOT / 'src/file_version.c'),
                        '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)
if __name__ == '__main__':
    main()
