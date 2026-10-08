#include "record_archive.h"
#include "editions.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_TAR_BLOCK  512U
#define RECORD_FRAME_SIZE 56U
typedef struct {
    Tb2WorkflowIO* io;
    Tb2RecordTask* task;
    void* file;
    uint32_t size;
    mbedtls_sha256_context hash;
    uint8_t bytes[TB2_RECORD_CHUNK];
    union {
        Tb2BoxVersion version;
        Tb2Edition edition;
        Tb2ServerPackage package;
    };
} RecordArchive;

static bool stopped(RecordArchive* a) {
    return a->io->cancelled && a->io->cancelled(a->io->context);
}
static bool join(char path[TB2_JOB_PATH_MAX], const char* root, const char* name) {
    int n = snprintf(path, TB2_JOB_PATH_MAX, "%s/%s", root, name);
    return n > 0 && n < (int)TB2_JOB_PATH_MAX;
}
static void digest_name(const uint8_t* digest, char out[65]) {
    for(unsigned i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", digest[i]);
}
static Tb2RecordResult write_bytes(RecordArchive* a, const void* data, size_t size) {
    if(stopped(a)) return Tb2RecordCancelled;
    if(size > UINT32_MAX - a->size || a->io->write(a->io->context, a->file, data, size) != size ||
       mbedtls_sha256_update(&a->hash, data, size))
        return Tb2RecordIo;
    a->size += (uint32_t)size;
    return Tb2RecordOk;
}
static Tb2RecordResult write_header(RecordArchive* a, const char* name, uint32_t size) {
    uint8_t header[RECORD_TAR_BLOCK] = {0};
    if(!name[0] || strlen(name) >= 100) return Tb2RecordCorrupt;
    memcpy(header, name, strlen(name));
    memcpy(header + 100, "0000600", 7);
    memcpy(header + 108, "0000000", 7);
    memcpy(header + 116, "0000000", 7);
    snprintf((char*)header + 124, 12, "%011lo", (unsigned long)size);
    memcpy(header + 136, "00000000000", 11);
    memset(header + 148, ' ', 8);
    header[156] = '0';
    memcpy(header + 257, "ustar", 5);
    memcpy(header + 263, "00", 2);
    unsigned sum = 0;
    for(unsigned i = 0; i < sizeof(header); i++)
        sum += header[i];
    snprintf((char*)header + 148, 7, "%06o", sum);
    header[155] = ' ';
    return write_bytes(a, header, sizeof(header));
}
static Tb2RecordResult pad(RecordArchive* a, uint32_t size) {
    const uint8_t zero[RECORD_TAR_BLOCK] = {0};
    size_t count = (RECORD_TAR_BLOCK - size % RECORD_TAR_BLOCK) % RECORD_TAR_BLOCK;
    return count ? write_bytes(a, zero, count) : Tb2RecordOk;
}
static Tb2RecordResult member(
    RecordArchive* a,
    const char* name,
    const char* path,
    uint32_t size,
    const uint8_t* expected) {
    Tb2WorkflowIO* io = a->io;
    void* input = io->open(io->context, path, Tb2FileRead);
    Tb2RecordResult rc = input && io->size(io->context, input) == size ? Tb2RecordOk : Tb2RecordIo;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if(!rc && mbedtls_sha256_starts(&sha, 0)) rc = Tb2RecordIo;
    if(!rc) rc = write_header(a, name, size);
    for(uint32_t offset = 0; !rc && offset < size;) {
        size_t count = size - offset;
        if(count > sizeof(a->bytes)) count = sizeof(a->bytes);
        if(io->read(io->context, input, a->bytes, count) != count ||
           mbedtls_sha256_update(&sha, a->bytes, count))
            rc = Tb2RecordIo;
        if(!rc) rc = write_bytes(a, a->bytes, count);
        offset += (uint32_t)count;
        if(io->progress) io->progress(io->context, "Export record", offset, size);
    }
    uint8_t digest[32];
    if(!rc && mbedtls_sha256_finish(&sha, digest)) rc = Tb2RecordIo;
    if(!rc && expected && memcmp(expected, digest, 32)) rc = Tb2RecordConflict;
    mbedtls_sha256_free(&sha);
    if(input && !io->close(io->context, input)) rc = Tb2RecordIo;
    if(!rc) rc = pad(a, size);
    return rc;
}
static Tb2RecordResult metadata(
    RecordArchive* a,
    const char* child,
    Tb2RecordKind kind,
    size_t payload_size,
    uint32_t generation) {
    char base[TB2_JOB_PATH_MAX], path[TB2_JOB_PATH_MAX], name[100];
    uint32_t current = 0;
    if(!tb2_record_path(base, a->task->box, child)) return Tb2RecordCorrupt;
    Tb2RecordResult rc =
        tb2_record_read(a->io, base, kind, a->task->box, a->bytes, payload_size, &current);
    if(rc) return rc;
    if(current != generation) return Tb2RecordConflict;
    int n = snprintf(path, sizeof(path), "%s.%u", base, (unsigned)(current & 1U));
    if(n <= 0 || n >= (int)sizeof(path)) return Tb2RecordCorrupt;
    snprintf(name, sizeof(name), "boxes/%s/%s.%u", a->task->box, child, (unsigned)(current & 1U));
    /* Recheck the selected raw generation, including its CRC and payload, so
     * a concurrent file replacement cannot enter an apparently valid export. */
    size_t size = payload_size + RECORD_FRAME_SIZE;
    uint8_t* raw = malloc(size);
    if(!raw) return Tb2RecordIo;
    void* f = a->io->open(a->io->context, path, Tb2FileRead);
    bool ok = f && a->io->size(a->io->context, f) == size &&
              a->io->read(a->io->context, f, raw, size) == size;
    if(f) ok = a->io->close(a->io->context, f) && ok;
    uint8_t hash[32];
    uint32_t crc = ok ? tb2_job_crc(raw, size - 4) : 0, stored = 0;
    if(ok)
        for(unsigned i = 0; i < 4; i++)
            stored |= (uint32_t)raw[size - 4 + i] << (i * 8);
    if(!ok)
        rc = Tb2RecordIo;
    else if(crc != stored || memcmp(raw + RECORD_FRAME_SIZE - 4, a->bytes, payload_size))
        rc = Tb2RecordConflict;
    else if(mbedtls_sha256(raw, size, hash, 0))
        rc = Tb2RecordIo;
    if(!rc) rc = member(a, name, path, (uint32_t)size, hash);
    tb2_record_wipe(raw, size);
    free(raw);
    return rc;
}
static Tb2RecordResult
    object_member(RecordArchive* a, const Tb2ObjectRef* ref, const char* fixed_name) {
    if(!ref->size) return fixed_name ? Tb2RecordMissing : Tb2RecordOk;
    char path[TB2_JOB_PATH_MAX], marker[TB2_JOB_PATH_MAX], hex[65], name[80];
    if(!tb2_object_path(path, ref)) return Tb2RecordCorrupt;
    digest_name(ref->digest, hex);
    snprintf(name, sizeof(name), "objects/%.2s/%s", hex, hex);
    if(!join(marker, a->task->staging, hex)) return Tb2RecordCorrupt;
    if(!fixed_name) {
        int exists = a->io->exists(a->io->context, marker);
        if(exists < 0) return Tb2RecordIo;
        if(exists) return Tb2RecordOk;
    }
    Tb2RecordResult rc = member(a, fixed_name ? fixed_name : name, path, ref->size, ref->digest);
    if(!rc && !fixed_name) {
        void* f = a->io->open(a->io->context, marker, Tb2FileNew);
        bool ok = f && a->io->sync(a->io->context, f);
        if(f) ok = a->io->close(a->io->context, f) && ok;
        if(!ok) rc = Tb2RecordIo;
    }
    return rc;
}
static Tb2RecordResult diagnostic_text(RecordArchive* a, const char* name, const char* message) {
    uint32_t size = (uint32_t)strlen(message);
    Tb2RecordResult rc = write_header(a, name, size);
    if(!rc) rc = write_bytes(a, message, size);
    if(!rc) rc = pad(a, size);
    return rc;
}
static Tb2RecordResult archive_entries(RecordArchive* a, char prefix) {
    Tb2RecordPage page;
    char anchor[TB2_RECORD_ID_SIZE] = {0};
    Tb2RecordResult rc;
    bool more;
    do {
        rc = tb2_record_page_open(a->io, &page, a->task->box, anchor, false);
        page.prefix = prefix;
        page.strict = true;
        while(!rc && !page.done)
            rc = tb2_record_page_step(a->io, &page, 4);
        more = page.more;
        for(unsigned i = 0; !rc && i < page.count; i++) {
            char child[40];
            snprintf(child, sizeof(child), "%c-%s", prefix, page.ids[i]);
            if(prefix == 'v') {
                rc = tb2_version_load(a->io, a->task->box, page.ids[i], &a->version);
                if(!rc && a->task->kind == Tb2RecordTaskDiagnostic) {
                    char message[256], name[80];
                    snprintf(name, sizeof(name), "versions/%s.txt", a->version.id);
                    snprintf(
                        message,
                        sizeof(message),
                        "Saved state\nVersion: %lu\nFlags: %lu\nFirmware: %s\nImage bytes: %lu\n",
                        (unsigned long)a->version.number,
                        (unsigned long)a->version.flags,
                        a->version.firmware.known ? a->version.firmware.version : "Unknown",
                        (unsigned long)a->version.image.size);
                    rc = diagnostic_text(a, name, message);
                    strcpy(anchor, page.ids[i]);
                    continue;
                }
                if(!rc)
                    rc = metadata(
                        a,
                        child,
                        Tb2RecordVersion,
                        TB2_VERSION_PAYLOAD_SIZE,
                        a->version.generation);
                bool deleted = (a->version.flags & Tb2VersionDeleted) != 0;
                if(!rc && !deleted) rc = object_member(a, &a->version.image, NULL);
                for(unsigned j = deleted ? 5 : 0; !rc && j < TB2_RECORD_ARTIFACTS; j++)
                    rc = object_member(a, &a->version.artifacts[j], NULL);
            } else if(prefix == 'f') {
                rc = tb2_edition_load(a->io, a->task->box, page.ids[i], &a->edition);
                if(!rc)
                    rc = metadata(
                        a,
                        child,
                        Tb2RecordEdition,
                        TB2_EDITION_PAYLOAD_SIZE,
                        a->edition.generation);
                /* A reserved binding may precede object publication. It remains
                 * historical pending metadata, never a complete imported image. */
                if(!rc && !(a->edition.flags & Tb2EditionPublished) && a->edition.image.size) {
                    char path[TB2_JOB_PATH_MAX];
                    if(!tb2_object_path(path, &a->edition.image))
                        rc = Tb2RecordCorrupt;
                    else {
                        int exists = a->io->exists(a->io->context, path);
                        if(exists < 0)
                            rc = Tb2RecordIo;
                        else if(exists)
                            rc = object_member(a, &a->edition.image, NULL);
                    }
                }
            } else if(prefix == 'p') {
                rc = tb2_server_package_load(a->io, a->task->box, page.ids[i], &a->package);
                if(!rc)
                    rc = metadata(
                        a,
                        child,
                        Tb2RecordPackage,
                        TB2_SERVER_PACKAGE_PAYLOAD_SIZE,
                        a->package.generation);
                for(unsigned j = 0; !rc && j < TB2_SERVER_PACKAGE_OBJECTS; j++)
                    rc = object_member(a, &a->package.objects[j], NULL);
            } else if(prefix == 'k') {
                Tb2BoxSecret key;
                rc = tb2_secret_load(a->io, a->task->box, page.ids[i], &key);
                if(!rc)
                    rc = metadata(
                        a, child, Tb2RecordSecret, TB2_SECRET_PAYLOAD_SIZE, key.generation);
                tb2_record_wipe(&key, sizeof(key));
            } else {
                Tb2BoxEntry entry;
                rc = tb2_entry_load(a->io, a->task->box, page.ids[i], prefix == 'n', &entry);
                if(!rc && a->task->kind == Tb2RecordTaskDiagnostic) {
                    char message[256], name[80];
                    snprintf(name, sizeof(name), "events/%s.txt", entry.id);
                    snprintf(
                        message,
                        sizeof(message),
                        "Saved state\nTime: %lu\nType: %lu\nState: %lu\nFlags: %lu\nResult: %ld\n",
                        (unsigned long)entry.timestamp,
                        (unsigned long)entry.type,
                        (unsigned long)entry.state,
                        (unsigned long)entry.flags,
                        (long)entry.code);
                    rc = diagnostic_text(a, name, message);
                } else if(!rc)
                    rc = metadata(
                        a,
                        child,
                        prefix == 'n' ? Tb2RecordNote : Tb2RecordEvent,
                        TB2_ENTRY_PAYLOAD_SIZE,
                        entry.generation);
            }
            strcpy(anchor, page.ids[i]);
        }
        tb2_record_page_close(a->io, &page);
    } while(!rc && more);
    return rc;
}
static Tb2RecordResult
    verify_archive(RecordArchive* a, const char* path, const uint8_t digest[32]) {
    Tb2WorkflowIO* io = a->io;
    void* f = io->open(io->context, path, Tb2FileRead);
    Tb2RecordResult rc = f && io->size(io->context, f) == a->size ? Tb2RecordOk : Tb2RecordIo;
    if(!rc && mbedtls_sha256_starts(&a->hash, 0)) rc = Tb2RecordIo;
    for(uint32_t offset = 0; !rc && offset < a->size;) {
        size_t count = a->size - offset;
        if(count > sizeof(a->bytes)) count = sizeof(a->bytes);
        if(stopped(a))
            rc = Tb2RecordCancelled;
        else if(
            io->read(io->context, f, a->bytes, count) != count ||
            mbedtls_sha256_update(&a->hash, a->bytes, count))
            rc = Tb2RecordIo;
        offset += (uint32_t)count;
    }
    uint8_t actual[32];
    if(!rc && mbedtls_sha256_finish(&a->hash, actual)) rc = Tb2RecordIo;
    if(!rc && memcmp(digest, actual, 32)) rc = Tb2RecordCorrupt;
    if(f && !io->close(io->context, f)) rc = Tb2RecordIo;
    return rc;
}
Tb2RecordResult tb2_record_archive(Tb2WorkflowIO* io, Tb2RecordTask* task) {
    RecordArchive* a = calloc(1, sizeof(*a));
    if(!a) return Tb2RecordIo;
    a->io = io;
    a->task = task;
    mbedtls_sha256_init(&a->hash);
    if(task->archive_receipt.size && io->exists(io->context, task->path) == 1) {
        a->size = task->archive_receipt.size;
        Tb2RecordResult checked = verify_archive(a, task->path, task->archive_receipt.digest);
        if(!checked)
            snprintf(task->report, sizeof(task->report), "Export checked.\n%s", task->path);
        mbedtls_sha256_free(&a->hash);
        tb2_record_wipe(a, sizeof(*a));
        free(a);
        return checked;
    }
    char id[TB2_RECORD_ID_SIZE], partial[TB2_JOB_PATH_MAX];
    Tb2RecordResult rc = tb2_record_new_id(io, id) ? Tb2RecordOk : Tb2RecordIo;
    /* Every attempt owns a fresh staging directory. Interrupted exports and
     * dedup markers cannot masquerade as members of a later retry. */
    if(!rc) {
        int n = snprintf(task->staging, sizeof(task->staging), "%s/export-%s", TB2_JOBS_ROOT, id);
        if(n <= 0 || n >= (int)sizeof(task->staging))
            rc = Tb2RecordCorrupt;
        else if(
            io->exists(io->context, task->staging) != 0 ||
            !io->mkdir(io->context, TB2_JOBS_ROOT) || !io->mkdir(io->context, task->staging))
            rc = Tb2RecordIo;
    }
    if(!rc && !task->path[0]) {
        snprintf(
            task->path,
            sizeof(task->path),
            "%s/%s-%s.%s.tar",
            TB2_APP_ROOT,
            task->box,
            id,
            task->kind == Tb2RecordTaskPackage    ? "package" :
            task->kind == Tb2RecordTaskDiagnostic ? "diagnostic" :
                                                    "tb2box");
    }
    if(!rc &&
       (!join(partial, task->staging, "export.part") || io->exists(io->context, task->path) != 0))
        rc = Tb2RecordConflict;
    if(!rc) {
        a->file = io->open(io->context, partial, Tb2FileNew);
        if(!a->file || mbedtls_sha256_starts(&a->hash, 0)) rc = Tb2RecordIo;
    }
    if(!rc && task->kind == Tb2RecordTaskPackage) {
        static const char* const names[] = {
            "ca-root.pem",
            "ca-key.pem",
            "teddy-cert.pem",
            "teddy-key.pem",
            "ici.pem",
            "ici.key",
            "ca.der"};
        rc = tb2_version_load(io, task->box, task->version, &a->version);
        for(unsigned i = 0; !rc && i < 7; i++)
            rc = object_member(a, &a->version.artifacts[5 + i], names[i]);
    } else if(!rc && task->kind == Tb2RecordTaskExport) {
        Tb2BoxRecord box;
        rc = tb2_box_load(io, task->box, &box);
        if(!rc) rc = metadata(a, "box", Tb2RecordBox, TB2_BOX_PAYLOAD_SIZE, box.generation);
        Tb2BoxFolder folder;
        if(!rc) {
            rc = tb2_folder_load(io, task->box, &folder);
            if(rc == Tb2RecordMissing)
                rc = Tb2RecordOk;
            else if(!rc)
                rc = metadata(
                    a, "files", Tb2RecordFolder, TB2_FOLDER_PAYLOAD_SIZE, folder.generation);
        }
        const char prefixes[] = "vknefp";
        for(unsigned i = 0; !rc && i < sizeof(prefixes) - 1; i++)
            rc = archive_entries(a, prefixes[i]);
    } else if(!rc && task->kind == Tb2RecordTaskDiagnostic) {
        rc = diagnostic_text(
            a,
            "diagnostic.txt",
            "TB2 Manager diagnostic\nSaved metadata only. Excludes images, secrets, key paths, certificates, settings, notes, aliases and serials.\n");
        if(!rc) rc = archive_entries(a, 'v');
        if(!rc) rc = archive_entries(a, 'e');
    } else if(!rc)
        rc = Tb2RecordCorrupt;
    const uint8_t zero[RECORD_TAR_BLOCK * 2] = {0};
    uint8_t digest[32];
    if(!rc) rc = write_bytes(a, zero, sizeof(zero));
    if(!rc && mbedtls_sha256_finish(&a->hash, digest)) rc = Tb2RecordIo;
    if(a->file) {
        bool synced = io->sync(io->context, a->file);
        bool closed = io->close(io->context, a->file);
        if(!synced || !closed) rc = Tb2RecordIo;
    }
    if(!rc) rc = verify_archive(a, partial, digest);
    if(!rc) {
        task->archive_receipt.size = a->size;
        memcpy(task->archive_receipt.digest, digest, sizeof(digest));
    }
    if(!rc && !io->move_new(io->context, partial, task->path)) rc = Tb2RecordIo;
    if(!rc) rc = verify_archive(a, task->path, digest);
    if(!rc)
        snprintf(
            task->report,
            sizeof(task->report),
            "Export checked.\n%s\n%s",
            task->path,
            task->kind == Tb2RecordTaskExport ?
                "Contains plaintext secrets and private keys. Results remain Saved state." :
            task->kind == Tb2RecordTaskDiagnostic ?
                "Redacted diagnostic metadata only." :
                "Seven server package files; image unchanged.");
    mbedtls_sha256_free(&a->hash);
    tb2_record_wipe(a, sizeof(*a));
    free(a);
    return rc;
}
