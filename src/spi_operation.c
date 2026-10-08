#include "operation.h"
#include "probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A pre-flash backup has its own immutable path and journal. It cannot change
 * the parent Flash input, nor overwrite an arbitrary user-selected file. */
static int backup_run(Tb2SpiTransport* transport, Tb2SpiRequest* request) {
    Tb2Operation* parent = request->operation;
    if(!parent || !request->directory || !request->receipt || !parent->approved ||
       parent->state != Tb2UiRunning)
        return TB2_PROBE_CHECK_FAILED;
    char directory[TB2_JOB_PATH_MAX], path[TB2_JOB_PATH_MAX], descriptor[TB2_JOB_PATH_MAX];
    int n = snprintf(directory, sizeof(directory), "%s/backup-job", request->directory);
    if(n < 0 || n >= (int)sizeof(directory)) return TB2_PROBE_CHECK_FAILED;
    n = snprintf(path, sizeof(path), "%s/backup.bin", request->directory);
    if(n < 0 || n >= (int)sizeof(path) || strcmp(path, request->path))
        return TB2_PROBE_CHECK_FAILED;
    n = snprintf(descriptor, sizeof(descriptor), "%s/%s", directory, TB2_OPERATION_NAME);
    if(n < 0 || n >= (int)sizeof(descriptor)) return TB2_PROBE_CHECK_FAILED;
    Tb2WorkflowIO* io = request->io;
    Tb2Operation* op = calloc(1, sizeof(*op));
    if(!op) return TB2_PROBE_IO_ERROR;
    int rc = TB2_PROBE_IO_ERROR;
    int exists = io->exists(io->context, descriptor);
    if(exists < 0 || !io->mkdir(io->context, directory)) goto done;
    bool loaded = exists && tb2_operation_load(io, directory, op);
    if(loaded) {
        if(op->kind != Tb2OperationDump || strcmp(op->source, path) || op->state == Tb2UiAborted)
            goto done;
    } else {
        if(exists && io->exists(io->context, path) != 0) goto done;
        memset(op, 0, sizeof(*op));
        op->kind = Tb2OperationDump;
        op->state = Tb2UiPrepared;
        strcpy(op->source, path);
        strcpy(op->created, parent->created);
        op->dump.flags = parent->flash.flags & (Tb2SpiBound | Tb2SpiManual);
        memcpy(op->dump.uid, parent->flash.uid, sizeof(op->dump.uid));
        if(!(exists ? tb2_operation_retry_create(io, directory, op) :
                      tb2_operation_create(io, directory, op)))
            goto done;
    }
    if((op->dump.flags & (Tb2SpiBound | Tb2SpiManual)) !=
           (parent->flash.flags & (Tb2SpiBound | Tb2SpiManual)) ||
       ((op->dump.flags & Tb2SpiBound) && memcmp(op->dump.uid, parent->flash.uid, 8))) {
        rc = TB2_PROBE_CHECK_FAILED;
        goto done;
    }
    op->state = Tb2UiRunning;
    if(!tb2_operation_save(io, directory, op, true)) goto done;
    Tb2SpiRequest child = *request;
    child.backup = false;
    child.operation = op;
    child.directory = directory;
    child.receipt = &op->dump;
    child.lease = NULL;
    child.action = (op->dump.flags & Tb2SpiDumpSaved) ? Tb2SpiVerifyRead : Tb2SpiRead;
    rc = tb2_spi_operation_run(transport, &child);
    if(!rc && child.action == Tb2SpiRead) {
        child.action = Tb2SpiVerifyRead;
        rc = tb2_spi_operation_run(transport, &child);
    }
    op->result = rc;
    op->state = rc == TB2_PROBE_CANCELLED ? Tb2UiPaused : rc ? Tb2UiFailed : Tb2UiComplete;
    if(!rc) op->phase = Tb2PhaseComplete;
    if(!tb2_operation_save(io, directory, op, false) && !rc) rc = TB2_PROBE_IO_ERROR;
done:
    *request->receipt = op->dump;
    free(op);
    return rc;
}

static bool persist(void* context, const Tb2SpiReceipt* receipt, Tb2SpiPhase phase) {
    Tb2SpiRequest* r = context;
    Tb2Operation* op = r->operation;
    if(receipt == &op->dump)
        op->phase = phase == Tb2SpiPhaseVerify ? Tb2PhaseSourceVerify : Tb2PhaseSource;
    else if(r->action == Tb2SpiPreflight)
        op->phase = Tb2PhaseFlashPrepare;
    else
        op->phase = (receipt->flags & Tb2SpiWriteDone) ? Tb2PhaseFlashVerify :
                                                         Tb2PhaseFlashProgram;
    return tb2_operation_save(r->io, r->directory, op, false);
}

int tb2_spi_operation_run(Tb2SpiTransport* transport, Tb2SpiRequest* request) {
    if(request->backup) return backup_run(transport, request);
    if(!request->operation) return tb2_spi_run(transport, request);
    Tb2Operation* op = request->operation;
    bool dump = request->action == Tb2SpiRead || request->action == Tb2SpiVerifyRead;
    if(!request->directory || !request->path || op->state != Tb2UiRunning ||
       strcmp(request->path, dump ? op->source : op->image) ||
       request->receipt != (dump ? &op->dump : &op->flash) ||
       ((request->action == Tb2SpiFlash || request->action == Tb2SpiVerifyFlash) && !op->approved))
        return TB2_PROBE_CHECK_FAILED;
    Tb2SpiRequest bound = *request;
    bound.context = &bound;
    bound.checkpoint = persist;
    return tb2_spi_run(transport, &bound);
}
