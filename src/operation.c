#include "operation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OP_MAGIC   0x364f4254U
#define OP_VERSION 3U
static void put32(uint8_t* out, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        out[i] = (uint8_t)(value >> (8U * i));
}
static uint32_t get32(const uint8_t* bytes) {
    uint32_t value = 0;
    for(unsigned i = 0; i < 4; i++)
        value |= (uint32_t)bytes[i] << (8U * i);
    return value;
}
static bool bin_path(const char* path) {
    const char* end = memchr(path, 0, TB2_JOB_PATH_MAX);
    if(!end || end - path < 10 || strncmp(path, "/ext/", 5) || strstr(path, "//") ||
       strstr(path, "/../") || strstr(path, "/./"))
        return false;
    for(const char* p = path; p < end; p++)
        if((unsigned char)*p < 32 || strchr("\\:*?\"<>|", *p)) return false;
    /* Internal immutable image objects have no extension. Only the canonical
     * SHA-256 namespace is accepted; arbitrary extensionless inputs are not. */
    const size_t root = sizeof(TB2_OBJECTS_ROOT "/") - 1;
    if(!strncmp(path, TB2_OBJECTS_ROOT "/", root) && (size_t)(end - path) == root + 67 &&
       path[root + 2] == '/' && path[root] == path[root + 3] && path[root + 1] == path[root + 4]) {
        for(const char* p = path + root + 3; p < end; p++)
            if(!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return false;
        return true;
    }
    return end[-4] == '.' && (end[-3] == 'b' || end[-3] == 'B') &&
           (end[-2] == 'i' || end[-2] == 'I') && (end[-1] == 'n' || end[-1] == 'N');
}
static bool child(char out[TB2_JOB_PATH_MAX], const char* directory, const char* name) {
    int size = snprintf(out, TB2_JOB_PATH_MAX, "%s/%s", directory, name);
    return size > 0 && size < (int)TB2_JOB_PATH_MAX;
}
static bool info_valid(const Tb2Operation* op) {
    if(op->kind < Tb2OperationDump || op->kind > Tb2OperationPureFlash ||
       (op->format && op->format < 3 && tb2_operation_pure(op->kind)) ||
       (op->format == 1 && op->kind > Tb2OperationModify) || op->created[TB2_DATE_SIZE - 1] ||
       !bin_path(op->source))
        return false;
    for(unsigned i = 0; i < TB2_DATE_SIZE - 1; i++)
        if(op->created[i] < '0' || op->created[i] > '9') return false;
    return true;
}
static void encode_info(const Tb2Operation* op, const char* directory, uint8_t* bytes) {
    memset(bytes, 0, TB2_OPERATION_SPEC_SIZE);
    put32(bytes, OP_MAGIC);
    put32(bytes + 4, op->format);
    put32(bytes + 8, op->kind);
    put32(bytes + 12, tb2_job_crc(directory, strlen(directory)));
    memcpy(bytes + 16, op->created, TB2_DATE_SIZE);
    memcpy(bytes + 31, op->source, strlen(op->source));
    put32(bytes + TB2_OPERATION_SPEC_SIZE - 4, tb2_job_crc(bytes, TB2_OPERATION_SPEC_SIZE - 4));
}
static bool read_exact(Tb2WorkflowIO* io, const char* path, void* bytes, size_t size) {
    void* file = io->open(io->context, path, Tb2FileRead);
    bool ok = file && io->size(io->context, file) == size &&
              io->read(io->context, file, bytes, size) == size;
    if(file) ok = io->close(io->context, file) && ok;
    return ok;
}
bool tb2_operation_info(Tb2WorkflowIO* io, const char* directory, Tb2Operation* op) {
    memset(op, 0, sizeof(*op));
    char path[TB2_JOB_PATH_MAX];
    uint8_t bytes[TB2_OPERATION_SPEC_SIZE];
    if(!child(path, directory, TB2_OPERATION_NAME) ||
       !read_exact(io, path, bytes, sizeof(bytes)) || get32(bytes) != OP_MAGIC ||
       (get32(bytes + 4) < 1U || get32(bytes + 4) > OP_VERSION) ||
       get32(bytes + 12) != tb2_job_crc(directory, strlen(directory)) ||
       get32(bytes + sizeof(bytes) - 4) != tb2_job_crc(bytes, sizeof(bytes) - 4))
        return false;
    op->kind = (Tb2OperationKind)get32(bytes + 8);
    op->format = (uint8_t)get32(bytes + 4);
    memcpy(op->created, bytes + 16, TB2_DATE_SIZE);
    memcpy(op->source, bytes + 31, TB2_JOB_PATH_MAX);
    op->descriptor_crc = get32(bytes + sizeof(bytes) - 4);
    op->state = Tb2UiPrepared;
    return info_valid(op);
}
static void put_receipt(uint8_t* bytes, const Tb2SpiReceipt* receipt) {
    put32(bytes, receipt->flags);
    memcpy(bytes + 4, receipt->uid, TB2_SPI_UID_SIZE);
    memcpy(bytes + 12, receipt->digest, 32);
}
static void get_receipt(const uint8_t* bytes, Tb2SpiReceipt* receipt) {
    receipt->flags = get32(bytes);
    memcpy(receipt->uid, bytes + 4, TB2_SPI_UID_SIZE);
    memcpy(receipt->digest, bytes + 12, 32);
}
static bool receipt_valid(const Tb2SpiReceipt* r) {
    if(r->flags & ~1023U) return false;
    uint32_t identity = r->flags & (Tb2SpiBound | Tb2SpiManual);
    if(identity == (Tb2SpiBound | Tb2SpiManual) || (r->flags && !identity)) return false;
    if((r->flags & Tb2SpiDumpSaved) && !(r->flags & Tb2SpiOwned)) return false;
    if((r->flags & Tb2SpiFileChecked) && !(r->flags & Tb2SpiDigestBound)) return false;
    if((r->flags & Tb2SpiWriteDone) && (r->flags & (Tb2SpiEraseStarted | Tb2SpiFileChecked)) !=
                                           (Tb2SpiEraseStarted | Tb2SpiFileChecked))
        return false;
    if((r->flags & Tb2SpiDumpVerified) &&
       (r->flags & (Tb2SpiDumpSaved | Tb2SpiDigestBound)) != (Tb2SpiDumpSaved | Tb2SpiDigestBound))
        return false;
    if((r->flags & Tb2SpiFlashVerified) &&
       (r->flags & (Tb2SpiWriteDone | Tb2SpiDigestBound)) != (Tb2SpiWriteDone | Tb2SpiDigestBound))
        return false;
    return true;
}
static bool state_valid(const Tb2Operation* op) {
    if(tb2_operation_pure(op->kind) &&
       (op->modify_bound || op->settings_only || op->archive.flags ||
        (op->phase != Tb2PhaseComplete &&
         (op->kind == Tb2OperationPureDump ?
              op->phase > Tb2PhaseSourceVerify :
              op->phase < Tb2PhaseFlashPrepare || op->phase > Tb2PhaseFlashVerify))))
        return false;
    if(op->format == 1 && ((op->dump.flags | op->flash.flags) & Tb2SpiManual)) return false;
    if(op->modify_bound && !bin_path(op->image)) return false;
    if(op->state == Tb2UiComplete) {
        if(op->phase != Tb2PhaseComplete) return false;
        if(tb2_operation_dump(op->kind) && !(op->dump.flags & Tb2SpiDumpVerified)) return false;
        if((tb2_operation_flash(op->kind) || op->kind == Tb2OperationAio ||
            op->kind == Tb2OperationRestore) &&
           !(op->flash.flags & Tb2SpiFlashVerified))
            return false;
        if((op->kind == Tb2OperationAio ||
            (op->kind == Tb2OperationModify && !op->settings_only)) &&
           (!op->modify_bound || !(op->archive.flags & TB2_ARCHIVE_VERIFIED)))
            return false;
    }
    return op->state >= Tb2UiPrepared && op->state <= Tb2UiAborted &&
           op->phase <= (op->format == 1 ? Tb2PhaseComplete : Tb2PhaseArchiveTarget) &&
           receipt_valid(&op->dump) && receipt_valid(&op->flash) && !(op->archive.flags & ~3U) &&
           (!(op->archive.flags & TB2_ARCHIVE_VERIFIED) ||
            (op->archive.flags & TB2_ARCHIVE_OWNED)) &&
           memchr(op->image, 0, sizeof(op->image)) && (!op->image[0] || bin_path(op->image));
}
static void encode_state(const Tb2Operation* op, uint8_t bytes[TB2_OPERATION_RECORD_SIZE]) {
    memset(bytes, 0, TB2_OPERATION_RECORD_SIZE);
    put32(bytes, OP_MAGIC);
    put32(bytes + 4, op->sequence);
    put32(bytes + 8, op->descriptor_crc);
    put32(bytes + 12, op->state);
    put32(bytes + 16, op->phase);
    put32(bytes + 20, (uint32_t)op->result);
    put32(
        bytes + 24,
        (op->approved ? 1U : 0) | (op->modify_bound ? 2U : 0) | (op->settings_only ? 4U : 0));
    put32(bytes + 28, op->spec_crc);
    put_receipt(bytes + 32, &op->dump);
    put_receipt(bytes + 76, &op->flash);
    put32(bytes + 120, op->archive.flags);
    memcpy(bytes + 124, op->archive.digest, 32);
    memcpy(bytes + 156, op->package_hash, 32);
    memcpy(bytes + 188, op->ca_hash, 32);
    memcpy(bytes + 220, op->image_hash, 32);
    memcpy(bytes + 252, op->image, strlen(op->image));
    put32(bytes + 508, tb2_job_crc(bytes, 508));
}
static bool decode_state(Tb2Operation* op, const uint8_t* bytes, uint32_t sequence) {
    if(get32(bytes) != OP_MAGIC || get32(bytes + 4) != sequence ||
       get32(bytes + 8) != op->descriptor_crc || get32(bytes + 508) != tb2_job_crc(bytes, 508) ||
       get32(bytes + 24) > 7)
        return false;
    op->sequence = sequence;
    op->state = (Tb2UiState)get32(bytes + 12);
    op->phase = (Tb2OperationPhase)get32(bytes + 16);
    op->result = (int32_t)get32(bytes + 20);
    op->approved = (get32(bytes + 24) & 1) != 0;
    op->modify_bound = (get32(bytes + 24) & 2) != 0;
    op->settings_only = (get32(bytes + 24) & 4) != 0;
    op->spec_crc = get32(bytes + 28);
    get_receipt(bytes + 32, &op->dump);
    get_receipt(bytes + 76, &op->flash);
    op->archive.flags = get32(bytes + 120);
    memcpy(op->archive.digest, bytes + 124, 32);
    memcpy(op->package_hash, bytes + 156, 32);
    memcpy(op->ca_hash, bytes + 188, 32);
    memcpy(op->image_hash, bytes + 220, 32);
    memcpy(op->image, bytes + 252, TB2_JOB_PATH_MAX);
    return state_valid(op);
}
bool tb2_operation_load(Tb2WorkflowIO* io, const char* directory, Tb2Operation* op) {
    if(!tb2_operation_info(io, directory, op)) return false;
    char path[TB2_JOB_PATH_MAX];
    if(!child(path, directory, TB2_OPERATION_JOURNAL)) return false;
    int exists = io->exists(io->context, path);
    if(!exists) return true;
    if(exists < 0) return false;
    void* file = io->open(io->context, path, Tb2FileRead);
    uint64_t size = file ? io->size(io->context, file) : UINT64_MAX;
    bool ok = size <= TB2_OPERATION_RECORD_LIMIT * TB2_OPERATION_RECORD_SIZE;
    uint32_t count = ok ? (uint32_t)(size / TB2_OPERATION_RECORD_SIZE) : 0;
    op->torn = ok && size % TB2_OPERATION_RECORD_SIZE != 0;
    /* Also reached from Jobs and terminal saves on the 4-KiB GUI stack. */
    uint8_t* bytes = ok && count ? malloc(TB2_OPERATION_RECORD_SIZE) : NULL;
    if(ok && count)
        ok = bytes && io->seek(io->context, file, (count - 1) * TB2_OPERATION_RECORD_SIZE) &&
             io->read(io->context, file, bytes, TB2_OPERATION_RECORD_SIZE) ==
                 TB2_OPERATION_RECORD_SIZE &&
             decode_state(op, bytes, count);
    if(file) ok = io->close(io->context, file) && ok;
    free(bytes);
    return ok;
}
static bool receipt_bound(const Tb2SpiReceipt* old, const Tb2SpiReceipt* current) {
    if((old->flags & Tb2SpiManual) && !(current->flags & Tb2SpiManual)) return false;
    if((old->flags & Tb2SpiBound) &&
       (!(current->flags & Tb2SpiBound) || memcmp(old->uid, current->uid, 8)))
        return false;
    if((old->flags & Tb2SpiDigestBound) &&
       (!(current->flags & Tb2SpiDigestBound) || memcmp(old->digest, current->digest, 32)))
        return false;
    return !(old->flags & Tb2SpiOwned) || (current->flags & Tb2SpiOwned);
}
bool tb2_operation_save(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2Operation* op,
    bool repair_tail) {
    if(!info_valid(op) || !state_valid(op)) return false;
    Tb2Operation* previous = malloc(sizeof(*previous));
    bool ok = previous && tb2_operation_load(io, directory, previous);
    if(ok)
        ok = op->format == previous->format && op->kind == previous->kind &&
             !strcmp(op->created, previous->created) && !strcmp(op->source, previous->source) &&
             op->settings_only == previous->settings_only && previous->state != Tb2UiAborted &&
             (!previous->torn || repair_tail) && previous->sequence < TB2_OPERATION_RECORD_LIMIT &&
             receipt_bound(&previous->dump, &op->dump) &&
             receipt_bound(&previous->flash, &op->flash) &&
             (!previous->modify_bound || (op->modify_bound && op->spec_crc == previous->spec_crc &&
                                          !strcmp(op->image, previous->image)));
    if(!ok) {
        free(previous);
        return false;
    }
    op->descriptor_crc = previous->descriptor_crc;
    uint32_t sequence = previous->sequence;
    free(previous);
    char path[TB2_JOB_PATH_MAX];
    if(!child(path, directory, TB2_OPERATION_JOURNAL)) return false;
    int exists = io->exists(io->context, path);
    if(exists < 0) return false;
    /* Terminal saves also run on the 4-KiB UI stack after worker join.
     * Keep both encoded records off that stack: readback descends through
     * load/info and resident SD logging while the original bytes stay live. */
    uint8_t* bytes = malloc(2U * TB2_OPERATION_RECORD_SIZE);
    if(!bytes) return false;
    void* file = io->open(io->context, path, exists ? Tb2FileUpdate : Tb2FileNew);
    uint32_t offset = sequence * TB2_OPERATION_RECORD_SIZE;
    ok = file && io->size(io->context, file) >= offset && io->seek(io->context, file, offset);
    if(ok && repair_tail) ok = io->truncate(io->context, file) && io->sync(io->context, file);
    op->sequence = sequence + 1;
    encode_state(op, bytes);
    if(ok)
        ok = io->write(io->context, file, bytes, TB2_OPERATION_RECORD_SIZE) ==
                 TB2_OPERATION_RECORD_SIZE &&
             io->sync(io->context, file);
    if(file) ok = io->close(io->context, file) && ok;
    Tb2Operation* check = malloc(sizeof(*check));
    if(ok)
        ok = check && tb2_operation_load(io, directory, check) && !check->torn &&
             check->sequence == op->sequence;
    if(ok) {
        uint8_t* saved = bytes + TB2_OPERATION_RECORD_SIZE;
        encode_state(check, saved);
        ok = !memcmp(bytes, saved, TB2_OPERATION_RECORD_SIZE);
    }
    free(check);
    free(bytes);
    op->torn = !ok;
    return ok;
}
static bool
    create_operation(Tb2WorkflowIO* io, const char* directory, Tb2Operation* op, bool retry) {
    if(!info_valid(op) || op->sequence || op->state != Tb2UiPrepared) return false;
    op->format = OP_VERSION;
    char path[TB2_JOB_PATH_MAX];
    if(!child(path, directory, TB2_OPERATION_NAME)) return false;
    uint8_t bytes[TB2_OPERATION_SPEC_SIZE], saved[TB2_OPERATION_SPEC_SIZE];
    encode_info(op, directory, bytes);
    if(retry) {
        char journal[TB2_JOB_PATH_MAX];
        if(!child(journal, directory, TB2_OPERATION_JOURNAL) ||
           io->exists(io->context, journal) != 0)
            return false;
        void* partial = io->open(io->context, path, Tb2FileRead);
        uint64_t size = partial ? io->size(io->context, partial) : UINT64_MAX;
        bool same = size < sizeof(bytes) &&
                    io->read(io->context, partial, saved, (size_t)size) == size &&
                    !memcmp(bytes, saved, (size_t)size);
        if(partial) same = io->close(io->context, partial) && same;
        if(!same) return false;
    }
    void* file = io->open(io->context, path, retry ? Tb2FileUpdate : Tb2FileNew);
    bool ok = file && io->write(io->context, file, bytes, sizeof(bytes)) == sizeof(bytes) &&
              io->sync(io->context, file);
    if(file) ok = io->close(io->context, file) && ok;
    if(ok) ok = read_exact(io, path, saved, sizeof(saved)) && !memcmp(bytes, saved, sizeof(bytes));
    return ok && tb2_operation_save(io, directory, op, false);
}
bool tb2_operation_create(Tb2WorkflowIO* io, const char* directory, Tb2Operation* op) {
    return create_operation(io, directory, op, false);
}
bool tb2_operation_retry_create(Tb2WorkflowIO* io, const char* directory, Tb2Operation* op) {
    return create_operation(io, directory, op, true);
}
