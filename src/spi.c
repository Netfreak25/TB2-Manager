/* Adapted from SPI Mem Manager at efc32b71838d3d5e8d604c1ba7a4793916d5212f.
 * See third_party/spi_mem_manager/provenance.json and LICENSE. */
#include "spi.h"
#include "operation.h"
#include "probe.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERASE_TIMEOUT_MS   220000U
#define PAGE_TIMEOUT_MS    1000U
#define DETECT_POLL_MS     50U
#define ERASE_POLL_MS      50U
#define PAGE_POLL_MS       1U
#define STATUS_BUSY        1U
#define STATUS_WEL         2U
#define STATUS_BP          0x1CU
#define STATUS_CMP         0x40U
#define STATUS_WPS         4U
#define UID_PROBE_ATTEMPTS 3U
#define FILE_HASH_CHUNK    (16U * 1024U)

typedef struct {
    Tb2SpiTransport* bus;
    Tb2SpiRequest* r;
    void* file;
    uint8_t* chip;
    uint8_t* bytes;
} Spi;

static bool cancelled(Spi* s) {
    return s->r->io->cancelled && s->r->io->cancelled(s->r->io->context);
}
static int failure(Spi* s, int rc, const char* text) {
    snprintf(s->r->result->error, sizeof(s->r->result->error), "%s", text);
    return rc;
}
static void
    progress(Spi* s, Tb2SpiPhase phase, const char* text, uint32_t offset, uint32_t total) {
    s->r->result->phase = phase;
    s->r->result->offset = offset;
    if(s->r->io->progress) s->r->io->progress(s->r->io->context, text, offset, total);
}
static int checkpoint(Spi* s) {
    return !s->r->checkpoint ||
                   s->r->checkpoint(s->r->context, s->r->receipt, s->r->result->phase) ?
               0 :
               failure(s, TB2_PROBE_IO_ERROR, "Cannot save operation checkpoint.");
}
static bool command(Spi* s, uint8_t cmd, uint8_t* bytes, size_t size) {
    return s->bus->transfer(s->bus->context, &cmd, 1, bytes, size);
}

/** Cancellation stops new commands, never pretends an active erase has stopped. */
static int ready(Spi* s, bool erase) {
    uint32_t start = s->bus->milliseconds(s->bus->context);
    uint32_t timeout = erase ? ERASE_TIMEOUT_MS : PAGE_TIMEOUT_MS;
    for(;;) {
        uint8_t status = 0;
        if(!command(s, 0x05, &status, 1))
            return failure(s, Tb2SpiTransportError, "Cannot read chip status. Retry connection.");
        if(!(status & STATUS_BUSY)) return cancelled(s) ? TB2_PROBE_CANCELLED : 0;
        if(s->bus->milliseconds(s->bus->context) - start >= timeout)
            return failure(
                s, Tb2SpiTimeout, "Chip busy timeout. State incomplete; retry when ready.");
        s->bus->delay(s->bus->context, erase ? ERASE_POLL_MS : PAGE_POLL_MS);
    }
}

static int detect(Spi* s) {
    progress(s, Tb2SpiPhaseDetect, "Waiting for chip", 0, 0);
    const uint8_t expected[] = {0xEF, 0x40, 0x18};
    unsigned uid_attempts = 0;
    for(;;) {
        if(cancelled(s)) return TB2_PROBE_CANCELLED;
        uint8_t id[3] = {0};
        bool ok = command(s, 0x9F, id, sizeof(id));
        if(ok && id[0] && id[0] != 255) {
            if(memcmp(id, expected, sizeof(id)))
                return failure(
                    s, Tb2SpiUnsupported, "Unsupported chip. W25Q128FV profile requires EF4018.");
            if(s->r->action == Tb2SpiCompare) return 0;
            uint8_t uid[TB2_SPI_UID_SIZE], verify[TB2_SPI_UID_SIZE];
            const uint8_t read_uid[] = {0x4B, 0, 0, 0, 0};
            bool stable =
                s->bus->transfer(s->bus->context, read_uid, sizeof(read_uid), uid, sizeof(uid)) &&
                s->bus->transfer(
                    s->bus->context, read_uid, sizeof(read_uid), verify, sizeof(verify));
            bool all_zero = true, all_ff = true;
            for(unsigned i = 0; stable && i < sizeof(uid); i++) {
                if(uid[i]) all_zero = false;
                if(uid[i] != 255) all_ff = false;
            }
            if(stable && !all_zero && !all_ff && !memcmp(uid, verify, sizeof(uid))) {
                s->r->result->uid_available = true;
                memcpy(s->r->result->uid, uid, sizeof(uid));
                if(((s->r->receipt->flags & Tb2SpiBound) &&
                    memcmp(s->r->receipt->uid, uid, sizeof(uid))) ||
                   (s->r->expected_uid && memcmp(s->r->expected_uid, uid, sizeof(uid))))
                    return failure(
                        s,
                        Tb2SpiDifferentChip,
                        "Different chip. Reconnect the original or start a new job.");
                if(!(s->r->receipt->flags & Tb2SpiManual)) {
                    memcpy(s->r->receipt->uid, uid, sizeof(uid));
                    s->r->receipt->flags |= Tb2SpiBound;
                }
                return checkpoint(s);
            }
            if(++uid_attempts >= UID_PROBE_ATTEMPTS && !(s->r->receipt->flags & Tb2SpiBound) &&
               ((s->r->probe_uid && s->r->action == Tb2SpiDetect) ||
                (s->r->receipt->flags & Tb2SpiManual)))
                return checkpoint(s);
        }
        /* Each transaction is bounded; connection waiting lasts until Back. */
        s->bus->delay(s->bus->context, DETECT_POLL_MS);
    }
}

static int read_chip(Spi* s, uint32_t offset, uint8_t* bytes, size_t size) {
    if(offset > TB2_IMAGE_SIZE || size > TB2_IMAGE_SIZE - offset) return TB2_PROBE_CHECK_FAILED;
    uint8_t cmd[] = {0x03, (uint8_t)(offset >> 16), (uint8_t)(offset >> 8), (uint8_t)offset};
    return s->bus->transfer(s->bus->context, cmd, sizeof(cmd), bytes, size) ?
               0 :
               failure(s, Tb2SpiTransportError, "Chip read failed. Retry the read operation.");
}
static bool firmware_read(void* context, uint32_t offset, void* bytes, size_t size) {
    return !read_chip(context, offset, bytes, size);
}
static bool firmware_cancelled(void* context) {
    return cancelled(context);
}
static void firmware_progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    progress(context, Tb2SpiPhaseFirmware, stage, done, total);
}
static int firmware(Spi* s) {
    Tb2Reader io = {
        .context = s,
        .image_size = TB2_IMAGE_SIZE,
        .read = firmware_read,
        .cancelled = firmware_cancelled,
        .progress = firmware_progress};
    return tb2_identity_firmwares(&io, &s->r->result->firmware, &s->r->result->secondary);
}

static bool close_file(Spi* s) {
    if(!s->file) return true;
    bool ok = s->r->io->close(s->r->io->context, s->file);
    s->file = NULL;
    return ok;
}
static int open_source(Spi* s) {
    if(s->r->lease && *s->r->lease) {
        s->file = *s->r->lease;
        *s->r->lease = NULL;
    } else {
        s->file = s->r->io->open(s->r->io->context, s->r->path, Tb2FileRead);
    }
    if(!s->file || s->r->io->size(s->r->io->context, s->file) != TB2_IMAGE_SIZE ||
       !s->r->io->seek(s->r->io->context, s->file, 0))
        return failure(
            s, TB2_PROBE_IO_ERROR, "Image must be a readable, complete 16-MiB BIN file.");
    return 0;
}

static int hash_file(Spi* s, uint8_t digest[32]) {
    Tb2WorkflowIO* io = s->r->io;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    int rc = mbedtls_sha256_starts(&sha, 0);
    for(uint32_t offset = 0; !rc && offset < TB2_IMAGE_SIZE; offset += FILE_HASH_CHUNK) {
        progress(s, Tb2SpiPhaseFile, "Checking flash file", offset, TB2_IMAGE_SIZE);
        if(cancelled(s)) rc = TB2_PROBE_CANCELLED;
        if(!rc && io->read(io->context, s->file, s->bytes, FILE_HASH_CHUNK) != FILE_HASH_CHUNK)
            rc = failure(s, TB2_PROBE_IO_ERROR, "Cannot read complete image. Check SD and retry.");
        if(!rc) rc = mbedtls_sha256_update(&sha, s->bytes, FILE_HASH_CHUNK);
    }
    if(!rc) rc = mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    if(!rc && !io->seek(io->context, s->file, 0)) rc = TB2_PROBE_IO_ERROR;
    return rc;
}

static int verify(Spi* s, bool flash) {
    Tb2WorkflowIO* io = s->r->io;
    /* Invalidate an older success before a new comparison, including power loss. */
    s->r->receipt->flags &= ~(uint32_t)(flash ? Tb2SpiFlashVerified : Tb2SpiDumpVerified);
    s->r->result->phase = Tb2SpiPhaseVerify;
    int rc = checkpoint(s);
    if(!rc && !s->file) rc = open_source(s);
    if(!rc && !io->seek(io->context, s->file, 0)) rc = TB2_PROBE_IO_ERROR;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if(!rc) rc = mbedtls_sha256_starts(&sha, 0);
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += TB2_SPI_CHUNK) {
        progress(
            s, Tb2SpiPhaseVerify, flash ? "Verify flash" : "Verify dump", off, TB2_IMAGE_SIZE);
        if(cancelled(s)) rc = TB2_PROBE_CANCELLED;
        if(!rc) rc = read_chip(s, off, s->chip, TB2_SPI_CHUNK);
        if(!rc && io->read(io->context, s->file, s->bytes, TB2_SPI_CHUNK) != TB2_SPI_CHUNK)
            rc = failure(s, TB2_PROBE_IO_ERROR, "SD read failed during verification.");
        if(!rc && memcmp(s->chip, s->bytes, TB2_SPI_CHUNK))
            rc = failure(
                s, Tb2SpiMismatch, "Chip and file differ. Retry verify or repeat the operation.");
        if(!rc) rc = mbedtls_sha256_update(&sha, s->bytes, TB2_SPI_CHUNK);
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    if(!rc && (s->r->receipt->flags & Tb2SpiDigestBound) &&
       memcmp(digest, s->r->receipt->digest, sizeof(digest)))
        rc = failure(s, Tb2SpiMismatch, "File fingerprint changed. Start a new job.");
    bool retain = flash && s->r->lease && s->r->operation &&
                  s->r->operation->kind == Tb2OperationAio && (s->r->receipt->flags & Tb2SpiBound);
    if(!retain && !close_file(s) && !rc) rc = TB2_PROBE_IO_ERROR;
    if(!rc) {
        memcpy(s->r->receipt->digest, digest, sizeof(digest));
        s->r->receipt->flags |= Tb2SpiDigestBound |
                                (flash ? Tb2SpiFlashVerified : Tb2SpiDumpVerified);
        rc = checkpoint(s);
    }
    return rc;
}

static int dump(Spi* s) {
    Tb2WorkflowIO* io = s->r->io;
    if(s->r->receipt->flags & Tb2SpiDigestBound)
        return failure(
            s, TB2_PROBE_CHECK_FAILED, "Verified original retained. Start a new dump job.");
    bool owned = (s->r->receipt->flags & Tb2SpiOwned) != 0;
    int present = io->exists(io->context, s->r->path);
    if(present < 0 || (present && !owned))
        return failure(
            s, TB2_PROBE_IO_ERROR, "Dump target exists or SD error. Choose a new filename.");
    s->file = io->open(io->context, s->r->path, present ? Tb2FileUpdate : Tb2FileNew);
    if(!s->file)
        return failure(s, TB2_PROBE_IO_ERROR, "Cannot open dump target. Retry SD access.");
    s->r->receipt->flags |= Tb2SpiOwned;
    s->r->receipt->flags &= ~(uint32_t)Tb2SpiDumpSaved;
    s->r->result->phase = Tb2SpiPhaseRead;
    int rc = checkpoint(s);
    if(!rc && (!io->seek(io->context, s->file, 0) || !io->truncate(io->context, s->file)))
        rc = TB2_PROBE_IO_ERROR;
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += TB2_SPI_CHUNK) {
        progress(s, Tb2SpiPhaseRead, "Reading dump", off, TB2_IMAGE_SIZE);
        if(cancelled(s)) rc = TB2_PROBE_CANCELLED;
        if(!rc) rc = read_chip(s, off, s->bytes, TB2_SPI_CHUNK);
        if(!rc && io->write(io->context, s->file, s->bytes, TB2_SPI_CHUNK) != TB2_SPI_CHUNK)
            rc = failure(s, TB2_PROBE_IO_ERROR, "Dump write failed. Check SD and retry read.");
    }
    if(!rc &&
       (!io->sync(io->context, s->file) || io->size(io->context, s->file) != TB2_IMAGE_SIZE))
        rc = TB2_PROBE_IO_ERROR;
    if(!close_file(s) && !rc) rc = TB2_PROBE_IO_ERROR;
    if(!rc) {
        s->r->receipt->flags |= Tb2SpiDumpSaved;
        rc = checkpoint(s);
    }
    return rc;
}

static int write_enable(Spi* s) {
    uint8_t status = 0;
    if(!command(s, 0x06, NULL, 0) || !command(s, 0x05, &status, 1))
        return failure(s, Tb2SpiTransportError, "Write-enable transfer failed. Retry flash.");
    return status & STATUS_WEL ?
               0 :
               failure(s, Tb2SpiProtected, "Chip refused write enable. Check write protection.");
}
static int protection(Spi* s) {
    progress(s, Tb2SpiPhaseFile, "Checking protection", 0, 0);
    uint8_t one = 0, two = 0, three = 0;
    if(!command(s, 0x05, &one, 1) || !command(s, 0x35, &two, 1) || !command(s, 0x15, &three, 1))
        return failure(
            s, Tb2SpiTransportError, "Cannot read protection status. Retry connection.");
    if(!(three & STATUS_WPS)) {
        if((one & STATUS_BP) || (two & STATUS_CMP))
            return failure(
                s,
                Tb2SpiProtected,
                "Chip protection configured. Protection settings are retained.");
        return 0;
    }
    for(uint32_t offset = 0; offset < TB2_IMAGE_SIZE;) {
        progress(s, Tb2SpiPhaseFile, "Checking block locks", offset, TB2_IMAGE_SIZE);
        if(cancelled(s)) return TB2_PROBE_CANCELLED;
        uint8_t cmd[] = {0x3D, (uint8_t)(offset >> 16), (uint8_t)(offset >> 8), (uint8_t)offset};
        uint8_t locked = 0;
        if(!s->bus->transfer(s->bus->context, cmd, sizeof(cmd), &locked, 1))
            return failure(
                s, Tb2SpiTransportError, "Cannot read block protection. Retry connection.");
        if(locked & 1U) return failure(s, Tb2SpiProtected, "A flash block is write protected.");
        offset += offset < 65536U || offset >= TB2_IMAGE_SIZE - 65536U ? 4096U : 65536U;
    }
    return 0;
}

static bool page_is_erased(const uint8_t* page) {
    for(size_t i = 0; i < TB2_SPI_PAGE; i++)
        if(page[i] != 0xFFU) return false;
    return true;
}

static int flash(Spi* s, bool fresh_lease) {
    Tb2WorkflowIO* io = s->r->io;
    if(!(s->r->receipt->flags & Tb2SpiFileChecked))
        return failure(s, TB2_PROBE_CHECK_FAILED, "Flash file has not been approved.");
    int rc = open_source(s);
    uint8_t digest[32];
    if(!rc && !fresh_lease) {
        rc = hash_file(s, digest);
        if(!rc && memcmp(digest, s->r->receipt->digest, sizeof(digest)))
            rc = failure(s, Tb2SpiMismatch, "Approved file changed. Start a new flash job.");
    }
    if(!rc) rc = protection(s);
    if(!rc) {
        progress(s, Tb2SpiPhaseErase, "Erasing chip", 0, 0);
        s->r->receipt->flags &= ~(uint32_t)(Tb2SpiWriteDone | Tb2SpiFlashVerified);
        s->r->receipt->flags |= Tb2SpiEraseStarted;
        rc = checkpoint(s);
    }
    if(!rc) rc = write_enable(s);
    if(!rc && !command(s, 0xC7, NULL, 0))
        rc = failure(s, Tb2SpiTransportError, "Erase command failed. Retry flash.");
    if(!rc) rc = ready(s, true);
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if(!rc) rc = mbedtls_sha256_starts(&sha, 0);
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += TB2_SPI_CHUNK) {
        progress(s, Tb2SpiPhaseWrite, "Writing chip", off, TB2_IMAGE_SIZE);
        if(cancelled(s)) rc = TB2_PROBE_CANCELLED;
        if(!rc && io->read(io->context, s->file, s->bytes, TB2_SPI_CHUNK) != TB2_SPI_CHUNK)
            rc = failure(s, TB2_PROBE_IO_ERROR, "SD read failed during write. Retry full flash.");
        if(!rc) rc = mbedtls_sha256_update(&sha, s->bytes, TB2_SPI_CHUNK);
        for(uint32_t page = 0; !rc && page < TB2_SPI_CHUNK; page += TB2_SPI_PAGE) {
            if(cancelled(s)) {
                rc = TB2_PROBE_CANCELLED;
                break;
            }
            /* Chip erase already produced FF. Avoid WREN, program and busy
             * polling for pages whose target content is still fully erased. */
            if(page_is_erased(s->bytes + page)) continue;
            rc = write_enable(s);
            uint32_t address = off + page;
            uint8_t cmd[4 + TB2_SPI_PAGE] = {
                0x02, (uint8_t)(address >> 16), (uint8_t)(address >> 8), (uint8_t)address};
            memcpy(cmd + 4, s->bytes + page, TB2_SPI_PAGE);
            if(!rc && !s->bus->transfer(s->bus->context, cmd, sizeof(cmd), NULL, 0))
                rc = failure(s, Tb2SpiTransportError, "Page write failed. Retry full flash.");
            if(!rc) rc = ready(s, false);
        }
    }
    if(!rc) rc = mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    if(!rc && memcmp(digest, s->r->receipt->digest, sizeof(digest)))
        rc = failure(s, Tb2SpiMismatch, "Image changed during programming. Flash not verified.");
    if(!rc) {
        s->r->receipt->flags |= Tb2SpiWriteDone;
        rc = checkpoint(s);
    }
    if(!rc) rc = verify(s, true);
    return rc;
}

/** Transient comparison: no hashes, receipts, checkpoints or output files. */
static int compare_contents(Spi* s) {
    int rc = open_source(s);
    bool different = false;
    for(uint32_t offset = 0; !rc && offset < TB2_IMAGE_SIZE; offset += TB2_SPI_CHUNK) {
        progress(s, Tb2SpiPhaseVerify, "Comparing chip", offset, TB2_IMAGE_SIZE);
        if(cancelled(s)) rc = TB2_PROBE_CANCELLED;
        if(!rc) rc = read_chip(s, offset, s->chip, TB2_SPI_CHUNK);
        if(!rc &&
           s->r->io->read(s->r->io->context, s->file, s->bytes, TB2_SPI_CHUNK) != TB2_SPI_CHUNK)
            rc = failure(s, TB2_PROBE_IO_ERROR, "Cannot read selected image. Check SD.");
        if(!rc && memcmp(s->chip, s->bytes, TB2_SPI_CHUNK)) different = true;
    }
    if(!rc) s->r->result->different = different;
    return rc;
}

int tb2_spi_run(Tb2SpiTransport* transport, Tb2SpiRequest* request) {
    if(!transport || !request || !request->io || !request->receipt || !request->result ||
       !request->path || (request->action > Tb2SpiFirmware && request->action != Tb2SpiCompare) ||
       ((request->receipt->flags & (Tb2SpiBound | Tb2SpiManual)) == (Tb2SpiBound | Tb2SpiManual)))
        return TB2_PROBE_CHECK_FAILED;
    memset(request->result, 0, sizeof(*request->result));
    Spi s = {.bus = transport, .r = request};
    bool fresh_lease = request->lease && *request->lease;
    bool compare_chip = request->action == Tb2SpiVerifyRead || request->action == Tb2SpiFlash ||
                        request->action == Tb2SpiVerifyFlash || request->action == Tb2SpiCompare;
    bool large_hash_buffer = request->action == Tb2SpiPreflight ||
                             (request->action == Tb2SpiFlash && !fresh_lease);
    s.bytes = malloc(large_hash_buffer ? FILE_HASH_CHUNK : TB2_SPI_CHUNK);
    s.chip = compare_chip ? malloc(TB2_SPI_CHUNK) : NULL;
    bool began = s.bytes && (!compare_chip || s.chip) && transport->begin(transport->context);
    int rc = began ? 0 : failure(&s, TB2_PROBE_IO_ERROR, "SPI or memory unavailable. Retry.");
    if(!rc) {
        if(request->waiting) request->waiting(request->wait_context, true);
        rc = detect(&s);
        if(request->waiting) request->waiting(request->wait_context, false);
    }
    /* Once connected, an active command still has its bounded busy deadline. */
    if(!rc && request->action != Tb2SpiDetect) {
        progress(&s, Tb2SpiPhaseDetect, "Checking chip", 0, 0);
        rc = ready(&s, true);
    }
    if(!rc) {
        switch(request->action) {
        case Tb2SpiDetect:
            break;
        case Tb2SpiCompare:
            rc = compare_contents(&s);
            break;
        case Tb2SpiFirmware:
            rc = firmware(&s);
            break;
        case Tb2SpiInspectFile:
        case Tb2SpiHeaders: /* Routed separately; never enters this full-operation path. */
            rc = failure(&s, TB2_PROBE_CHECK_FAILED, "Invalid hardware action.");
            break;
        case Tb2SpiRead:
            rc = dump(&s);
            break;
        case Tb2SpiVerifyRead:
            rc = request->receipt->flags & Tb2SpiDumpSaved ?
                     verify(&s, false) :
                     failure(&s, TB2_PROBE_CHECK_FAILED, "No complete dump. Retry read first.");
            break;
        case Tb2SpiPreflight: {
            rc = open_source(&s);
            uint8_t digest[32];
            if(!rc) rc = hash_file(&s, digest);
            if(!rc && (request->receipt->flags & Tb2SpiFileChecked) &&
               memcmp(digest, request->receipt->digest, sizeof(digest)))
                rc = failure(&s, Tb2SpiMismatch, "Selected file changed. Start a new job.");
            if(!rc) {
                memcpy(request->receipt->digest, digest, sizeof(digest));
                request->receipt->flags |= Tb2SpiFileChecked | Tb2SpiDigestBound;
                rc = protection(&s);
            }
            if(!rc && request->lease) {
                *request->lease = s.file;
                s.file = NULL;
            }
            break;
        }
        case Tb2SpiFlash:
            rc = flash(&s, fresh_lease);
            break;
        case Tb2SpiVerifyFlash:
            rc = (request->receipt->flags & (Tb2SpiFileChecked | Tb2SpiWriteDone)) ==
                         (Tb2SpiFileChecked | Tb2SpiWriteDone) ?
                     verify(&s, true) :
                     failure(
                         &s, TB2_PROBE_CHECK_FAILED, "Programming incomplete. Retry full flash.");
            break;
        }
    }
    /* Keep the verified AIO output under the resident owner's exclusive lease.
     * A result-menu reflash can reuse it; import/navigation explicitly releases it. */
    if(!rc && s.file && request->lease && request->operation &&
       request->operation->kind == Tb2OperationAio &&
       (request->action == Tb2SpiFlash || request->action == Tb2SpiVerifyFlash) &&
       (request->receipt->flags & Tb2SpiBound)) {
        *request->lease = s.file;
        s.file = NULL;
    }
    if(!close_file(&s) && !rc) rc = TB2_PROBE_IO_ERROR;
    if(rc && request->action != Tb2SpiDetect && request->action != Tb2SpiPreflight &&
       request->action != Tb2SpiFirmware) {
        request->receipt->flags &=
            ~(uint32_t)(request->action == Tb2SpiRead || request->action == Tb2SpiVerifyRead ?
                            Tb2SpiDumpVerified :
                            Tb2SpiFlashVerified);
    }
    if(rc && request->lease && *request->lease) {
        request->io->close(request->io->context, *request->lease);
        *request->lease = NULL;
    }
    if(began) transport->end(transport->context);
    free(s.chip);
    free(s.bytes);
    if(rc && !request->result->error[0])
        failure(
            &s,
            rc,
            rc == TB2_PROBE_CANCELLED ? "Stopped. Files retained; retry available." :
                                        "SPI or SD operation failed. Retry available.");
    return rc;
}
