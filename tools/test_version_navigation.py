"""Compile the production AIO result menu and import handoff without a GUI SDK."""
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def block(text, anchor):
    start = text.index(anchor)
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[opening:end]

HARNESS = r'''
#include "setup.h"
#include "record_tasks.h"
#include "probe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/* ENUM */
typedef struct { Tb2SetupRequest* request; void* menu; } Aux;
static unsigned count;
static const char* names[20];
static AuxAction actions[20];
static void aux_add(Aux*a,const char*name,AuxAction action){(void)a;assert(count<20);names[count]=name;actions[count++]=action;}
static void submenu_set_header(void*m,const char*t){(void)m;(void)t;}
static void aux_items(Aux*a,const char*h,const char*text,uint8_t n,AuxAction first){(void)h;for(unsigned i=0;i<n;i++){aux_add(a,text,first+i);text+=strlen(text)+1;}}
static void action_menu(Aux*a){/* ACTION_LABELS */ /* ACTION_MENU */}
static void menu(Aux*a){do /* MENU */ while(0);}
static bool start_import(Tb2SetupRequest*r){/* IMPORT */ return false;}
#define IMPORT_TEXT 1
static unsigned stopped, shown, work_calls;
typedef struct {Tb2SetupRequest* request; void* dispatcher; unsigned view;} ImportUI;
static bool picked;
static void view_dispatcher_stop(void*d){(void)d;stopped++;}
static void import_show(ImportUI*u){(void)u;shown++;}
static bool import_browser(ImportUI*u,const char*ext){(void)u;assert(!strcmp(ext,".bin"));return picked;}
static void import_work(ImportUI*u,Tb2RecordTaskKind kind){u->request->record_task->kind=kind;work_calls++;}
static bool version_back(ImportUI*u){/* BACK */return false;}
static void normal_import(ImportUI*u){Tb2RecordTask*t=u->request->record_task;Tb2ImportDraft*d=&t->import;/* NORMAL */}
static bool open_duplicate(ImportUI*u){Tb2RecordTask*t=u->request->record_task;Tb2ImportDraft*d=&t->import;/* DUPLICATE */return false;}
static int find(const char*name){for(unsigned i=0;i<count;i++)if(!strcmp(names[i],name))return actions[i];return -1;}
int main(void){
 Tb2Operation op={.kind=Tb2OperationAio,.state=Tb2UiComplete,.phase=Tb2PhaseComplete};
 op.flash.flags=Tb2SpiBound|Tb2SpiFlashVerified;
 Tb2RecordTask task={0};Tb2SetupRequest request={.operation=&op,.record_task=&task};Aux a={.request=&request};
 action_menu(&a);assert(count==5 && find("Dump")==AuxDump && find("Flash")==AuxFlash && find("Modify")==AuxModify && find("AIO")==AuxAio && find("Core Flasher")==AuxFlipTdi);count=0;
 menu(&a);assert(find("Flash dump")==AuxProgram && find("Import")==AuxAioImport);
 count=0;request.historical=true;menu(&a);assert(find("Flash dump")==-1 && find("Import")==-1);
 request.historical=false;count=0;op.flash.flags=0;menu(&a);assert(find("Flash dump")==-1 && find("Import")==AuxAioImport);
 count=0;op.kind=Tb2OperationPureFlash;menu(&a);assert(find("Flash dump")==-1 && find("Import")==-1);
 op.kind=Tb2OperationAio;op.state=Tb2UiFailed;count=0;menu(&a);assert(find("Flash dump")==-1 && find("Import")==-1);
 op.state=Tb2UiComplete;request.kind=Tb2SetupAioImport;strcpy(request.box_id,"bound-box");
 strcpy(op.source,"/original.bin");strcpy(op.image,"/modified.bin");
 assert(start_import(&request));assert(request.action==Tb2SetupActionRecordTask);
 assert(task.kind==Tb2RecordTaskImportInspect && task.import.image_kind==Tb2ImageModified);
 assert(!strcmp(task.box,"bound-box") && !strcmp(task.path,"/modified.bin") && !task.import.identity_checked);
 ImportUI u={.request=&request};task.kind=Tb2RecordTaskRenamePrepare;strcpy(request.version_id,"selected-version");
 assert(version_back(&u) && stopped==1 && request.action==Tb2SetupActionBoxes);
 assert(!strcmp(request.version_id,"selected-version") && !work_calls);
 u.view=IMPORT_TEXT;assert(version_back(&u) && shown==1 && stopped==1);
 task.kind=Tb2RecordTaskCompareChip;u.view=0;assert(version_back(&u) && stopped==2);
 task.import.image_kind=Tb2ImageModified;task.flags=17;strcpy(task.version,"old-version");
 picked=false;normal_import(&u);assert(task.flags==17 && !work_calls);
 picked=true;normal_import(&u);assert(!task.flags && !task.version[0] && task.import.image_kind==Tb2ImageUnclassified && work_calls==1);
 task.import.duplicate=true;strcpy(task.version,"existing-version");assert(open_duplicate(&u));
 assert(!strcmp(request.version_id,"existing-version") && stopped==3 && work_calls==1);
 task.flags=TB2_RECORD_MOVE_SOURCE;assert(!open_duplicate(&u));
 puts("PASS: Back, duplicate handoff, normal import reset, AIO result visibility, UID requirement, original excluded, bound-box Modified import");
}
'''

def main():
    aux = (ROOT / 'src/setup_aux.c').read_text()
    ui = (ROOT / 'src/imports_ui.c').read_text()
    enum_start = aux.rfind('typedef enum', 0, aux.index('AuxBoxesOpen'))
    enum_end = aux.index('} AuxAction;', enum_start) + len('} AuxAction;')
    controller = (ROOT / 'src/app.c').read_text()
    header = (ROOT / 'src/setup.h').read_text()
    kinds = re.search(r'typedef enum \{(.*?)\} Tb2SetupKind;', header, re.DOTALL)[1]
    kinds = [item.strip() for item in kinds.split(',') if item.strip()]
    table = re.search(r'setup_modules\[[^]]+\] = \{(.*?)\};', controller, re.DOTALL)[1]
    entries = [item.strip() for item in table.split(',') if item.strip()]
    assert len(kinds) == len(entries)
    routes = dict(zip(kinds, entries))
    assert routes['Tb2SetupFirmwareHeaders'] == 'ModuleImports'
    assert routes['Tb2SetupAioImport'] == 'ModuleImports | SetupNeedsTask'
    assert all(routes[k] == 'ModuleAux' for k in ('Tb2SetupActions', 'Tb2SetupManage', 'Tb2SetupImages'))
    source_text = HARNESS.replace('/* ENUM */', aux[enum_start:enum_end])
    source_text = source_text.replace('/* MENU */', block(aux, 'case AuxHardware: {'))
    source_text = source_text.replace('/* IMPORT */', block(ui, 'if(r->kind == Tb2SetupAioImport)'))
    source_text = source_text.replace('/* BACK */', 'if(u->request->record_task && u->request->record_task->kind >= Tb2RecordTaskRenamePrepare)' + block(ui, 'if(u->request->record_task && u->request->record_task->kind >= Tb2RecordTaskRenamePrepare)'))
    source_text = source_text.replace('/* NORMAL */', 'if(import_browser(u, ".bin"))' + block(ui, 'if(import_browser(u, ".bin"))'))
    duplicate = block(ui, 'if(d->duplicate && !(t->flags & TB2_RECORD_MOVE_SOURCE))')
    source_text = source_text.replace('/* DUPLICATE */', 'if(d->duplicate && !(t->flags & TB2_RECORD_MOVE_SOURCE))' + duplicate[:-1] + 'return true;}')
    labels = re.search(r'static const char actions\[\] = .*?;', aux)[0]
    source_text = source_text.replace('/* ACTION_LABELS */', labels)
    action_branch = aux.split('case AuxActions:', 1)[1].split('break;', 1)[0]
    source_text = source_text.replace('/* ACTION_MENU */', action_branch)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'navigation.c'
        binary = Path(tmp) / 'navigation'
        source.write_text(source_text)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'src'), str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)

if __name__ == '__main__':
    main()
