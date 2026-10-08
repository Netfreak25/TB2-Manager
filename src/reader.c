#include "reader.h"
#include "backend.h"
#include "identity.h"
#include "probe.h"
#include "tb2_config_select.h"

#include <lfs.h>
#include <mbedtls/aes.h>
#include <mbedtls/asn1.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CACHE_SIZE       256U
#define LOOKAHEAD_SIZE   16U
#define REQUIRED_FILES   3U
#define HASH_CHUNK       2048U
#define LFS_MAGIC_OFFSET 8U

typedef struct {
    Tb2WorkflowIO* io;
    void* file;
    const char* directory;
} IdentityFile;
static bool identity_file_read(void* context, uint32_t offset, void* bytes, size_t size) {
    IdentityFile* f = context;
    return f->io->seek(f->io->context, f->file, offset) &&
           f->io->read(f->io->context, f->file, bytes, size) == size;
}
static bool identity_file_cancelled(void* context) {
    IdentityFile* f = context;
    return f->io->cancelled && f->io->cancelled(f->io->context);
}
static void
    identity_file_progress(void* context, const char* stage, uint32_t done, uint32_t total) {
    IdentityFile* f = context;
    if(f->io->progress) f->io->progress(f->io->context, stage, done, total);
}
static bool identity_file_event(void* context, const char* event, int code, const char* detail) {
    IdentityFile* f = context;
    return !f->io->event || f->io->event(f->io->context, event, code, detail);
}
static bool identity_file_backup(void* context, const char* name, const void* bytes, size_t size) {
    IdentityFile* f = context;
    Tb2WorkflowIO* io = f->io;
    char path[TB2_JOB_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", f->directory, name);
    if(n <= 0 || n >= (int)sizeof(path) || !size || size > TB2_CRYPT_MAX) return false;
    int exists = io->exists(io->context, path);
    if(exists < 0) return false;
    void* file = io->open(io->context, path, exists ? Tb2FileUpdate : Tb2FileNew);
    bool ok = file != NULL;
    if(ok)
        ok = io->write(io->context, file, bytes, size) == size &&
             io->truncate(io->context, file) && io->sync(io->context, file);
    if(file) ok = io->close(io->context, file) && ok;
    if(!ok) return false;
    uint8_t* saved = malloc(size);
    file = saved ? io->open(io->context, path, Tb2FileRead) : NULL;
    ok = file && io->size(io->context, file) == size &&
         io->read(io->context, file, saved, size) == size && !memcmp(saved, bytes, size);
    if(file) ok = io->close(io->context, file) && ok;
    free(saved);
    return ok;
}
int tb2_identity_file(
    Tb2WorkflowIO* io,
    const char* path,
    const char* directory,
    Tb2ImageIdentity* identity,
    bool reuse) {
    if(directory && !io->mkdir(io->context, directory)) return TB2_PROBE_IO_ERROR;
    IdentityFile f = {
        .io = io, .directory = directory, .file = io->open(io->context, path, Tb2FileRead)};
    if(!f.file) return TB2_PROBE_IO_ERROR;
    Tb2Reader reader = {
        .context = &f,
        .image_size = io->size(io->context, f.file),
        .read = identity_file_read,
        .cancelled = identity_file_cancelled,
        .event = identity_file_event,
        .backup = directory ? identity_file_backup : NULL,
        .progress = identity_file_progress};
    int rc = reuse && identity->filesystem_known ? tb2_reader_artifacts(&reader, identity) :
                                                   tb2_reader_identity(&reader, identity);
    if(!io->close(io->context, f.file)) rc = TB2_PROBE_IO_ERROR;
    return rc;
}

static const char* const cert_names[REQUIRED_FILES] = {
    "ca.der.crypt",
    "client.der.crypt",
    "private.der.crypt"};
static const char* const profiles[] = {"firmware_constants", "image_static_ram_init"};
static const uint8_t firmware_salt[16] =
    {0xbc, 0x21, 0x55, 0x13, 0x17, 0xda, 0x98, 0x1e, 0x5e, 0x46, 0x50, 0xa7, 0xd2, 0x38, 0xea, 0x2c};
static const uint8_t firmware_info[16] =
    {0x24, 0x69, 0x03, 0x1c, 0x24, 0x90, 0xad, 0x3f, 0x3b, 0xd1, 0xb0, 0x5c, 0xfd, 0x5c, 0x66, 0x81};

typedef struct {
    Tb2Reader* io;
    Tb2ReadResult* result;
    Tb2ServerValues* server_values;
    Tb2ServerRecords* server_records;
    lfs_t lfs;
    struct lfs_config cfg;
    uint32_t base;
    uint32_t limit;
    bool io_failed;
    bool mounted;
    uint8_t read_cache[CACHE_SIZE], prog_cache[CACHE_SIZE], lookahead[LOOKAHEAD_SIZE];
    uint8_t encrypted[TB2_CRYPT_MAX];
    /* Mbed TLS CBC supports in-place operation (also used by its self-test).
     * Each candidate is reread before decoding; backups precede decoding. */
    uint8_t* plain;
} Reader;

static bool event(Reader* reader, const char* op, int code, const char* detail) {
    if(!reader->io->event(reader->io->context, op, code, detail)) reader->io_failed = true;
    return !reader->io_failed;
}

static int fail(Reader* reader, int code, const char* message) {
    snprintf(reader->result->error, sizeof(reader->result->error), "%s", message);
    event(reader, "reader_error", code, message);
    return reader->io_failed ? TB2_PROBE_IO_ERROR : code;
}

static int checkpoint(Reader* reader, const char* stage, uint32_t done, uint32_t total) {
    reader->io->progress(reader->io->context, stage, done, total);
    if(reader->io_failed) return TB2_PROBE_IO_ERROR;
    return reader->io->cancelled(reader->io->context) ? TB2_PROBE_CANCELLED : 0;
}

static bool read_source(Reader* reader, uint32_t offset, void* data, size_t size) {
    if(offset > TB2_IMAGE_SIZE || size > TB2_IMAGE_SIZE - offset) return false;
    if(!reader->io->read(reader->io->context, offset, data, size)) reader->io_failed = true;
    return !reader->io_failed;
}

static int lfs_read(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    void* data,
    lfs_size_t size) {
    Reader* reader = cfg->context;
    if(reader->io->cancelled(reader->io->context)) return LFS_ERR_IO;
    if(block >= reader->limit / TB2_LFS_BLOCK_SIZE || off > TB2_LFS_BLOCK_SIZE ||
       size > TB2_LFS_BLOCK_SIZE - off)
        return LFS_ERR_CORRUPT;
    return read_source(reader, reader->base + block * TB2_LFS_BLOCK_SIZE + off, data, size) ?
               0 :
               LFS_ERR_IO;
}

/* The source interface deliberately has no write, erase or sync callback. */
static int lfs_no_prog(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    const void* data,
    lfs_size_t size) {
    (void)block;
    (void)off;
    (void)data;
    (void)size;
    event(cfg->context, "forbidden_source_write", LFS_ERR_IO, "source is read-only");
    return LFS_ERR_IO;
}
static int lfs_no_erase(const struct lfs_config* cfg, lfs_block_t block) {
    return lfs_no_prog(cfg, block, 0, NULL, 0);
}
static int lfs_no_sync(const struct lfs_config* cfg) {
    (void)cfg;
    return 0;
}

static uint32_t u32le(const uint8_t* data) {
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 |
           (uint32_t)data[3] << 24;
}

static int hash_source(Reader* reader, uint8_t digest[32]) {
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += HASH_CHUNK) {
        rc = checkpoint(reader, "Checking source", off, TB2_IMAGE_SIZE);
        if(!rc && !read_source(reader, off, reader->encrypted, HASH_CHUNK))
            rc = TB2_PROBE_IO_ERROR;
        if(!rc) rc = mbedtls_sha256_update(&hash, reader->encrypted, HASH_CHUNK);
    }
    if(!rc) rc = mbedtls_sha256_finish(&hash, digest);
    mbedtls_sha256_free(&hash);
    return rc;
}

static bool public_digest(Reader* reader, const char* op, const uint8_t* bytes, size_t size) {
    uint8_t digest[32];
    char hex[65];
    if(mbedtls_sha256(bytes, size, digest, 0)) return false;
    for(size_t i = 0; i < sizeof(digest); i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    return event(reader, op, 0, hex);
}

static int mount_at(Reader* reader, uint32_t base) {
    reader->base = base;
    reader->limit = TB2_IMAGE_SIZE - base;
    reader->cfg.block_count = 0; /* Use CRC-validated metadata, not a guessed size. */
    int rc = lfs_mount(&reader->lfs, &reader->cfg);
    reader->mounted = rc == 0;
    return rc;
}

/** Avoid feeding arbitrary firmware data into the LittleFS metadata walker.
 * A v2 filesystem stores the canonical superblock name in either member of
 * its leading metadata pair. The complete mount and geometry checks remain
 * authoritative; this is only a cheap candidate filter. */
static int has_littlefs_superblock(Reader* reader, uint32_t base) {
    static const uint8_t magic[] = {'l', 'i', 't', 't', 'l', 'e', 'f', 's'};
    uint8_t bytes[sizeof(magic)];
    const uint32_t offsets[] = {
        base + LFS_MAGIC_OFFSET,
        base + TB2_LFS_BLOCK_SIZE + LFS_MAGIC_OFFSET,
    };
    for(size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        if(!read_source(reader, offsets[i], bytes, sizeof(bytes))) return -1;
        if(!memcmp(bytes, magic, sizeof(magic))) return 1;
    }
    return 0;
}

static void unmount(Reader* reader) {
    if(reader->mounted) {
        int rc = lfs_unmount(&reader->lfs);
        if(rc) reader->io_failed = true;
        reader->mounted = false;
    }
}

static int read_cert(Reader* reader, const char* name, size_t* size);
static int select_profile(Reader* reader, const Tb2InputKey* input, bool export_plain);

static bool valid_container(const uint8_t* bytes, size_t size) {
    return size >= 33 && size <= TB2_CRYPT_MAX && (size - 17) % 16 == 0 && bytes[0] >= 1 &&
           bytes[0] <= 16;
}

static void configure_reader(Reader* reader) {
    reader->cfg = (struct lfs_config){
        .context = reader,
        .read = lfs_read,
        .prog = lfs_no_prog,
        .erase = lfs_no_erase,
        .sync = lfs_no_sync,
        .read_size = 16,
        .prog_size = 16,
        .block_size = TB2_LFS_BLOCK_SIZE,
        .block_cycles = -1,
        .cache_size = CACHE_SIZE,
        .lookahead_size = LOOKAHEAD_SIZE,
        .read_buffer = reader->read_cache,
        .prog_buffer = reader->prog_cache,
        .lookahead_buffer = reader->lookahead};
}

/** Frame scan deliberately knows only this exact key. Unknown record bodies,
 * including credentials, are skipped without interpreting or logging them. */
static int read_box_id(Reader* reader, char out[TB2_IDENTITY_BOX_SIZE]) {
    lfs_file_t file;
    uint8_t cache[CACHE_SIZE];
    struct lfs_file_config config = {.buffer = cache};
    int rc = lfs_file_opencfg(&reader->lfs, &file, "/settings", LFS_O_RDONLY, &config);
    if(rc) return rc;
    lfs_soff_t length = lfs_file_size(&reader->lfs, &file);
    unsigned matches = 0;
    const char key[] = "toniebox/id=";
    if(length <= 0 || length > (lfs_soff_t)TB2_SETTINGS_MAX) rc = LFS_ERR_CORRUPT;
    for(lfs_soff_t offset = 0; !rc && offset < length;) {
        uint8_t bytes[TB2_IDENTITY_BOX_SIZE + sizeof(key)];
        if(reader->io->cancelled(reader->io->context)) {
            rc = TB2_PROBE_CANCELLED;
            break;
        }
        if(length - offset < 2 ||
           lfs_file_seek(&reader->lfs, &file, offset, LFS_SEEK_SET) != offset ||
           lfs_file_read(&reader->lfs, &file, bytes, 2) != 2) {
            rc = LFS_ERR_CORRUPT;
            break;
        }
        uint32_t size = bytes[0] | (uint32_t)bytes[1] << 8;
        if(!size || size > (uint32_t)(length - offset - 2)) {
            rc = LFS_ERR_CORRUPT;
            break;
        }
        if(size >= sizeof(key) - 1) {
            if(lfs_file_read(&reader->lfs, &file, bytes, sizeof(key) - 1) != sizeof(key) - 1) {
                rc = LFS_ERR_IO;
                break;
            }
            if(!memcmp(bytes, key, sizeof(key) - 1)) {
                size_t count = size - (sizeof(key) - 1);
                if(++matches != 1 || !count || count >= TB2_IDENTITY_BOX_SIZE ||
                   lfs_file_read(&reader->lfs, &file, out, count) != (lfs_ssize_t)count) {
                    rc = LFS_ERR_CORRUPT;
                    break;
                }
                for(size_t i = 0; i < count; i++)
                    if((unsigned char)out[i] < 33 || (unsigned char)out[i] > 126)
                        rc = LFS_ERR_CORRUPT;
                out[count] = 0;
            }
        }
        offset += 2 + (lfs_soff_t)size;
    }
    int closed = lfs_file_close(&reader->lfs, &file);
    if(!rc) rc = closed;
    if(rc || matches != 1) memset(out, 0, TB2_IDENTITY_BOX_SIZE);
    return rc;
}

static int identity_artifacts(Reader* reader, Tb2ImageIdentity* identity) {
    static const char* const names[] = {
        "ca.der.crypt",
        "client.der.crypt",
        "private.der.crypt",
        "ap-mode-auth.cred.crypt",
        "ici-auth.cred.crypt"};
    identity->artifacts = 0;
    for(unsigned i = 0; reader->io->backup && i < 5; i++) {
        if(reader->io->cancelled(reader->io->context)) return TB2_PROBE_CANCELLED;
        size_t size = 0;
        int rc = read_cert(reader, names[i], &size);
        if(rc == LFS_ERR_NOENT) continue;
        if(rc) return reader->io_failed ? TB2_PROBE_IO_ERROR : 0;
        if(!reader->io->backup(reader->io->context, names[i], reader->encrypted, size))
            return TB2_PROBE_IO_ERROR;
        identity->artifacts |= (uint8_t)(1U << i);
    }
    return 0;
}
int tb2_reader_artifacts(Tb2Reader* io, Tb2ImageIdentity* identity) {
    if(!identity->filesystem_known || !io->backup) return TB2_PROBE_CHECK_FAILED;
    Reader* reader = calloc(1, sizeof(*reader));
    if(!reader) return TB2_PROBE_IO_ERROR;
    reader->io = io;
    configure_reader(reader);
    int rc = mount_at(reader, identity->offset);
    struct lfs_fsinfo info = {0};
    if(!rc) rc = lfs_fs_stat(&reader->lfs, &info);
    if(!rc &&
       (info.block_size != TB2_LFS_BLOCK_SIZE || info.block_count != identity->block_count ||
        info.disk_version != identity->disk_version))
        rc = LFS_ERR_CORRUPT;
    if(!rc) {
        reader->limit = identity->block_count * TB2_LFS_BLOCK_SIZE;
        rc = identity_artifacts(reader, identity);
    }
    unmount(reader);
    if(reader->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(rc < 0) rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_platform_zeroize(reader, sizeof(*reader));
    free(reader);
    return rc;
}
int tb2_reader_identity(Tb2Reader* io, Tb2ImageIdentity* identity) {
    if(!io || !identity || !io->read || !io->cancelled || !io->progress || !io->event)
        return TB2_PROBE_CHECK_FAILED;
    memset(identity, 0, sizeof(*identity));
    int rc = tb2_identity_firmwares(io, &identity->firmware, &identity->secondary);
    if(rc) return rc;
    Reader* reader = calloc(1, sizeof(*reader));
    if(!reader) return TB2_PROBE_IO_ERROR;
    reader->io = io;
    configure_reader(reader);
    unsigned matches = 0;
    for(uint32_t base = 0; base <= TB2_IMAGE_SIZE - 2U * TB2_LFS_BLOCK_SIZE;
        base += TB2_LFS_BLOCK_SIZE) {
        if(io->cancelled(io->context)) {
            rc = TB2_PROBE_CANCELLED;
            break;
        }
        io->progress(io->context, "Identify box", base, TB2_IMAGE_SIZE);
        int superblock = has_littlefs_superblock(reader, base);
        if(superblock < 0) {
            rc = TB2_PROBE_IO_ERROR;
            break;
        }
        if(!superblock) continue;
        int candidate = mount_at(reader, base);
        struct lfs_fsinfo info = {0};
        if(!candidate) candidate = lfs_fs_stat(&reader->lfs, &info);
        if(!candidate && (info.block_size != TB2_LFS_BLOCK_SIZE || info.block_count < 2 ||
                          info.block_count > reader->limit / TB2_LFS_BLOCK_SIZE))
            candidate = LFS_ERR_CORRUPT;
        if(!candidate) {
            reader->limit = info.block_count * TB2_LFS_BLOCK_SIZE;
            for(unsigned i = 0; !candidate && i < REQUIRED_FILES; i++) {
                size_t size = 0;
                candidate = read_cert(reader, cert_names[i], &size);
                if(!candidate && !valid_container(reader->encrypted, size))
                    candidate = LFS_ERR_CORRUPT;
            }
        }
        if(!candidate) {
            matches++;
            identity->offset = base;
            identity->block_count = info.block_count;
            identity->disk_version = info.disk_version;
        }
        unmount(reader);
        if(reader->io_failed) {
            rc = TB2_PROBE_IO_ERROR;
            break;
        }
        if(matches > 1) break;
    }
    if(!rc && matches == 1) {
        int mounted = mount_at(reader, identity->offset);
        if(!mounted) {
            reader->limit = identity->block_count * TB2_LFS_BLOCK_SIZE;
            identity->filesystem_known = true;
            int settings = read_box_id(reader, identity->box_id);
            if(settings == TB2_PROBE_CANCELLED) rc = settings;
            if(!rc) rc = identity_artifacts(reader, identity);
        }
    } else {
        identity->offset = identity->block_count = identity->disk_version = 0;
    }
    unmount(reader);
    if(reader->io_failed) rc = TB2_PROBE_IO_ERROR;
    mbedtls_platform_zeroize(reader, sizeof(*reader));
    free(reader);
    if(rc) memset(identity, 0, sizeof(*identity));
    return rc;
}

static int discover(Reader* reader, const Tb2InputKey* input) {
    unsigned matches = 0;
    unsigned structural_matches = 0;
    char detail[192];
    for(uint32_t base = 0; base <= TB2_IMAGE_SIZE - 2U * TB2_LFS_BLOCK_SIZE;
        base += TB2_LFS_BLOCK_SIZE) {
        int rc = checkpoint(reader, "Finding LittleFS", base, TB2_IMAGE_SIZE);
        if(rc) return rc;
        int superblock = has_littlefs_superblock(reader, base);
        if(superblock < 0) return TB2_PROBE_IO_ERROR;
        if(!superblock) continue;
        rc = mount_at(reader, base);
        const char* reason = "mount rejected";
        struct lfs_fsinfo fsinfo = {0};
        if(!rc) {
            rc = lfs_fs_stat(&reader->lfs, &fsinfo);
            reason = "metadata geometry rejected";
            if(!rc && (fsinfo.block_size != TB2_LFS_BLOCK_SIZE || fsinfo.block_count < 2 ||
                       fsinfo.block_count > reader->limit / TB2_LFS_BLOCK_SIZE))
                rc = LFS_ERR_CORRUPT;
            if(!rc) {
                reader->limit = fsinfo.block_count * TB2_LFS_BLOCK_SIZE;
                for(unsigned i = 0; !rc && i < REQUIRED_FILES; i++) {
                    char path[64];
                    struct lfs_info info;
                    snprintf(path, sizeof(path), "/cert/%s", cert_names[i]);
                    rc = lfs_stat(&reader->lfs, path, &info);
                    if(!rc && info.type != LFS_TYPE_REG) rc = LFS_ERR_ISDIR;
                    /* A shifted root-pair alias can mount and stat while its
                     * relative file-data pointers refer to different blocks. */
                    size_t size = 0;
                    if(!rc) rc = read_cert(reader, cert_names[i], &size);
                    if(!rc && !valid_container(reader->encrypted, size)) rc = LFS_ERR_CORRUPT;
                    if(rc) reason = cert_names[i];
                }
            }
            if(!rc) {
                structural_matches++;
                /* Metadata-pair aliases can even reference another syntactically
                 * valid .crypt blob. Confirm full DER and identity in RAM before
                 * choosing an origin; no candidate data is exported here. */
                rc = select_profile(reader, input, false);
                reason = "original DER/client-key validation rejected";
            }
            if(!rc) {
                matches++;
                reader->result->offset = base;
                reader->result->block_count = fsinfo.block_count;
                reader->result->disk_version = fsinfo.disk_version;
                reason = "mounted; required certificate files present";
            }
        }
        snprintf(
            detail,
            sizeof(detail),
            "offset=0x%08lx block_size=%lu count=%lu end=0x%llx reason=%s",
            (unsigned long)base,
            (unsigned long)fsinfo.block_size,
            (unsigned long)fsinfo.block_count,
            (unsigned long long)base + (uint64_t)fsinfo.block_size * fsinfo.block_count,
            reason);
        event(reader, "lfs_candidate", rc, detail);
        unmount(reader);
        if(reader->io_failed) return TB2_PROBE_IO_ERROR;
        if(matches > 1)
            return fail(
                reader,
                TB2_PROBE_CHECK_FAILED,
                "Multiple matching LittleFS regions; none selected.");
    }
    if(!matches && structural_matches)
        return fail(
            reader,
            TB2_PROBE_CHECK_FAILED,
            "Key does not match this box.\nSelect the correct box and key. Certificate data may also be damaged.");
    if(!matches)
        return fail(
            reader,
            TB2_PROBE_CHECK_FAILED,
            "Box filesystem not found.\nThe dump may be incomplete, damaged or unsupported.");
    int rc = mount_at(reader, reader->result->offset);
    if(rc) return fail(reader, TB2_PROBE_CHECK_FAILED, "Cannot remount selected region.");
    reader->limit = reader->result->block_count * TB2_LFS_BLOCK_SIZE;
    return 0;
}

static bool safe_name(const char* name) {
    if(!*name || *name == '.') return false;
    for(const char* p = name; *p; p++) {
        if(!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
             *p == '.' || *p == '-' || *p == '_'))
            return false;
    }
    return true;
}

static bool crypt_name(const char* name) {
    size_t size = strlen(name);
    return size > 6 && !strcmp(name + size - 6, ".crypt");
}

static int read_cert(Reader* reader, const char* name, size_t* size) {
    char path[LFS_NAME_MAX + 8];
    snprintf(path, sizeof(path), "/cert/%s", name);
    lfs_file_t file;
    int rc = lfs_file_open(&reader->lfs, &file, path, LFS_O_RDONLY);
    if(rc) return rc;
    lfs_soff_t length = lfs_file_size(&reader->lfs, &file);
    if(length < 33 || length > (lfs_soff_t)sizeof(reader->encrypted)) rc = LFS_ERR_FBIG;
    if(!rc) {
        lfs_ssize_t actual = lfs_file_read(&reader->lfs, &file, reader->encrypted, length);
        if(actual != length)
            rc = actual < 0 ? actual : LFS_ERR_IO;
        else
            *size = length;
    }
    int closed = lfs_file_close(&reader->lfs, &file);
    return rc ? rc : closed;
}

static int
    save(Reader* reader, const char* folder, const char* name, const void* data, size_t size) {
    if(reader->io_failed) return TB2_PROBE_IO_ERROR;
    char path[LFS_NAME_MAX + 32];
    snprintf(path, sizeof(path), "%s/%s", folder, name);
    if(!reader->io->backup(reader->io->context, path, data, size)) {
        reader->io_failed = true;
        return fail(reader, TB2_PROBE_IO_ERROR, "Backup write, sync or readback failed; see log.");
    }
    return 0;
}

static int backup_originals(Reader* reader) {
    lfs_dir_t dir;
    struct lfs_info info;
    int rc = lfs_dir_open(&reader->lfs, &dir, "/cert");
    if(rc) return fail(reader, TB2_PROBE_CHECK_FAILED, "Cannot read certificate folder.");
    while((rc = lfs_dir_read(&reader->lfs, &dir, &info)) > 0) {
        if(!crypt_name(info.name)) continue;
        rc = checkpoint(reader, "Backing up originals", 0, 0);
        if(rc) break;
        if(info.type != LFS_TYPE_REG || !safe_name(info.name)) {
            rc = LFS_ERR_INVAL;
            break;
        }
        size_t size = 0;
        rc = read_cert(reader, info.name, &size);
        if(rc) {
            event(reader, "original_read", rc, info.name);
            break;
        }
        const char* folder = strstr(info.name, ".cred.crypt") ? "credentials" : "original";
        rc = save(reader, folder, info.name, reader->encrypted, size);
        if(rc) break;
        reader->result->encrypted_files++;
    }
    int closed = lfs_dir_close(&reader->lfs, &dir);
    if(!rc) rc = closed;
    if(rc < 0)
        return fail(
            reader,
            TB2_PROBE_CHECK_FAILED,
            "Original unreadable, too large or unsafe filename; originals not replaced.");
    return rc;
}

static int decrypt(Reader* reader, const uint8_t key[16], size_t size, size_t* plain_size) {
    uint8_t pad = reader->encrypted[0];
    if(size < 33 || size > TB2_CRYPT_MAX || (size - 17) % 16 || !pad || pad > 16)
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    uint8_t iv[16];
    memcpy(iv, reader->encrypted + 1, sizeof(iv));
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int rc = mbedtls_aes_setkey_dec(&aes, key, 128);
    if(!rc)
        rc = mbedtls_aes_crypt_cbc(
            &aes, MBEDTLS_AES_DECRYPT, size - 17, iv, reader->encrypted + 17, reader->plain);
    mbedtls_aes_free(&aes);
    if(rc) return rc;
    *plain_size = size - 17 - pad;
    if(!*plain_size || *plain_size > TB2_PLAIN_MAX) return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    for(size_t i = *plain_size; i < size - 17; i++)
        if(reader->plain[i]) return MBEDTLS_ERR_ASN1_INVALID_DATA;
    return 0;
}

static int full_der(const uint8_t* data, size_t size) {
    unsigned char* cursor = (unsigned char*)data;
    size_t length = 0;
    int rc = mbedtls_asn1_get_tag(
        &cursor, data + size, &length, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    return rc ? rc :
                (length == (size_t)(data + size - cursor) ? 0 : MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
}

static bool log_certificate(Reader* reader, const char* name, mbedtls_x509_crt* cert) {
    char detail[192];
    snprintf(
        detail,
        sizeof(detail),
        "%s algorithm=%s bits=%lu validity=%04d%02d%02d-%04d%02d%02d dates_not_evaluated=1",
        name,
        mbedtls_pk_get_name(&cert->pk),
        (unsigned long)mbedtls_pk_get_bitlen(&cert->pk),
        cert->valid_from.year,
        cert->valid_from.mon,
        cert->valid_from.day,
        cert->valid_to.year,
        cert->valid_to.mon,
        cert->valid_to.day);
    return event(reader, "certificate_parsed", 0, detail) &&
           public_digest(reader, "public_certificate_sha256", cert->raw.p, cert->raw.len);
}

static int validate_set(Reader* reader, const uint8_t key[16], bool export_plain) {
    mbedtls_x509_crt cert;
    mbedtls_pk_context private_key;
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&private_key);
    int rc = 0;
    for(unsigned i = 0; !rc && i < REQUIRED_FILES; i++) {
        rc = checkpoint(reader, "Checking identity", i, REQUIRED_FILES);
        size_t size = 0, plain_size = 0;
        if(!rc) rc = read_cert(reader, cert_names[i], &size);
        if(!rc) {
            rc = decrypt(reader, key, size, &plain_size);
            event(reader, "crypt_decrypt", rc, cert_names[i]);
        }
        if(!rc) {
            rc = full_der(reader->plain, plain_size);
            event(reader, "der_complete", rc, cert_names[i]);
        }
        if(!rc && i < 2) {
            mbedtls_x509_crt_free(&cert);
            mbedtls_x509_crt_init(&cert);
            rc = mbedtls_x509_crt_parse_der(&cert, reader->plain, plain_size);
            event(reader, "x509_parse", rc, cert_names[i]);
            if(!rc && !log_certificate(reader, cert_names[i], &cert)) rc = TB2_PROBE_IO_ERROR;
        } else if(!rc) {
            rc = mbedtls_pk_parse_key(
                &private_key,
                reader->plain,
                plain_size,
                NULL,
                0,
                reader->io->random,
                reader->io->context);
            event(reader, "private_key_parse", rc, cert_names[i]);
            if(!rc) {
                rc = mbedtls_pk_check_pair(
                    &cert.pk, &private_key, reader->io->random, reader->io->context);
                event(
                    reader,
                    "client_key_pair",
                    rc,
                    "client.der / private.der; no private values logged");
            }
        }
        if(!event(reader, "original_decode_parse", rc, cert_names[i])) rc = TB2_PROBE_IO_ERROR;
        if(!rc && export_plain) {
            if(i < 2)
                rc = mbedtls_sha256(
                    reader->plain,
                    plain_size,
                    i ? reader->result->client_sha256 : reader->result->ca_sha256,
                    0);
            char name[32];
            snprintf(name, sizeof(name), "%.*s", (int)(strlen(cert_names[i]) - 6), cert_names[i]);
            if(!rc) rc = save(reader, "client", name, reader->plain, plain_size);
        }
        mbedtls_platform_zeroize(reader->plain, TB2_PLAIN_MAX + 16U);
    }
    mbedtls_pk_free(&private_key);
    mbedtls_x509_crt_free(&cert);
    return reader->io_failed ? TB2_PROBE_IO_ERROR : rc;
}

static int select_profile(Reader* reader, const Tb2InputKey* input, bool export_plain) {
    if(input->kind == Tb2InputKeyAes) {
        int rc = validate_set(reader, input->bytes, export_plain);
        if(!event(reader, "direct_aes_result", rc, "full DER and client-key validation"))
            return TB2_PROBE_IO_ERROR;
        if(!rc) reader->result->profile = 3;
        return rc;
    }
    uint8_t salts[2][16], infos[2][16], key[16] = {0}, accepted[16] = {0};
    memcpy(salts[0], firmware_salt, 16);
    memcpy(infos[0], firmware_info, 16);
    if(!read_source(reader, TB2_LEGACY_SALT_OFFSET, salts[1], 16) ||
       !read_source(reader, TB2_LEGACY_INFO_OFFSET, infos[1], 16))
        return TB2_PROBE_IO_ERROR;
    unsigned matches = 0;
    int rc = 0;
    for(unsigned i = 0; i < 2; i++) {
        if(i && !memcmp(salts[0], salts[1], 16) && !memcmp(infos[0], infos[1], 16)) {
            event(reader, "kdf_duplicate", 0, profiles[i]);
            continue;
        }
        rc = checkpoint(reader, "Checking KDF profile", i, 2);
        if(rc) break;
        rc = mbedtls_hkdf(
            mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
            salts[i],
            16,
            input->bytes,
            TB2_SN_SIZE,
            infos[i],
            16,
            key,
            sizeof(key));
        if(!rc) rc = validate_set(reader, key, false);
        event(reader, "kdf_result", rc, profiles[i]);
        if(rc == TB2_PROBE_CANCELLED || reader->io_failed) break;
        if(!rc) {
            matches++;
            reader->result->profile = i + 1;
            memcpy(accepted, key, sizeof(accepted));
        }
    }
    if(reader->io_failed)
        rc = TB2_PROBE_IO_ERROR;
    else if(reader->io->cancelled(reader->io->context))
        rc = TB2_PROBE_CANCELLED;
    else if(matches != 1)
        rc = fail(
            reader,
            TB2_PROBE_CHECK_FAILED,
            matches ? "Multiple KDF profiles verified; no plaintext exported." :
                      "No KDF profile validates all DER files and the client key pair. See log.");
    else
        rc = export_plain ? validate_set(reader, accepted, true) : 0;
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(accepted, sizeof(accepted));
    return rc;
}

typedef struct {
    Reader* reader;
    lfs_file_t file;
} ServerPreview;
static bool server_preview_read(void* context, uint32_t offset, void* bytes, size_t size) {
    ServerPreview* p = context;
    return lfs_file_seek(&p->reader->lfs, &p->file, offset, LFS_SEEK_SET) == (lfs_soff_t)offset &&
           lfs_file_read(&p->reader->lfs, &p->file, bytes, size) == (lfs_ssize_t)size;
}
static bool server_preview_cancelled(void* context) {
    ServerPreview* p = context;
    return p->reader->io->cancelled(p->reader->io->context);
}
static int server_preview(Reader* reader) {
    ServerPreview preview = {.reader = reader};
    int rc = lfs_file_open(&reader->lfs, &preview.file, "/settings", LFS_O_RDONLY);
    if(rc) return rc;
    lfs_soff_t size = lfs_file_size(&reader->lfs, &preview.file);
    if(size <= 0 || size > (lfs_soff_t)TB2_SETTINGS_MAX) rc = TB2_PROBE_CHECK_FAILED;
    Tb2SettingsIO io = {
        .context = &preview,
        .size = (uint32_t)size,
        .read = server_preview_read,
        .cancelled = server_preview_cancelled};
    Tb2ServerChange change = {0};
    bool changed;
    if(!rc)
        rc = reader->server_records ?
                 tb2_server_records_read(&io, reader->server_records) :
                 tb2_server_transform(&io, &change, reader->server_values, &changed);
    int closed = lfs_file_close(&reader->lfs, &preview.file);
    return rc ? rc : closed;
}

static int inspect(Reader* reader, const Tb2InputKey* input) {
    if(reader->io->image_size != TB2_IMAGE_SIZE)
        return fail(reader, TB2_PROBE_CHECK_FAILED, "Source must be exactly 16 MiB.");
    if(!read_source(reader, TB2_PRIMARY_OFFSET, reader->encrypted, 32)) return TB2_PROBE_IO_ERROR;
    uint32_t header_size = reader->encrypted[8] | (uint32_t)reader->encrypted[9] << 8;
    uint32_t image_size = u32le(reader->encrypted + 12);
    if(u32le(reader->encrypted) != TB2_MCUBOOT_MAGIC || header_size < 32 ||
       header_size > TB2_SLOT_SIZE || !image_size || image_size > TB2_SLOT_SIZE - header_size)
        return fail(
            reader,
            TB2_PROBE_CHECK_FAILED,
            "Invalid MCUboot header or payload in primary TB2 slot (no signature verification).");
    int rc = hash_source(reader, reader->result->source_sha256);
    if(!rc) {
        char hex[65];
        for(size_t i = 0; i < 32; i++)
            snprintf(hex + 2 * i, 3, "%02x", reader->result->source_sha256[i]);
        if(!event(reader, "source_sha256", 0, hex)) rc = TB2_PROBE_IO_ERROR;
    }
    if(!rc) rc = discover(reader, input);
    if(reader->server_values) {
        if(!rc) rc = server_preview(reader);
    } else {
        if(!rc) rc = backup_originals(reader);
        if(!rc) rc = select_profile(reader, input, true);
        if(!rc && reader->server_records) rc = server_preview(reader);
    }
    if(!rc) {
        uint8_t after[32];
        rc = hash_source(reader, after);
        if(!rc && memcmp(after, reader->result->source_sha256, sizeof(after)))
            rc = fail(
                reader,
                TB2_PROBE_CHECK_FAILED,
                "Source changed during processing; backup not released.");
    }
    return rc;
}

int tb2_reader_run(Tb2Reader* io, const uint8_t serial[TB2_SN_SIZE], Tb2ReadResult* result) {
    if(!serial) return TB2_PROBE_CHECK_FAILED;
    Tb2InputKey input = {.kind = Tb2InputKeySecret};
    memcpy(input.bytes, serial, TB2_SN_SIZE);
    int rc = tb2_reader_run_key(io, &input, result);
    mbedtls_platform_zeroize(&input, sizeof(input));
    return rc;
}

static int reader_run(
    Tb2Reader* io,
    const Tb2InputKey* input,
    Tb2ReadResult* result,
    Tb2ServerValues* values,
    Tb2ServerRecords* records) {
    if(!io || !input || !result || !io->read || !io->event || !io->cancelled || !io->progress ||
       (!values && !io->backup) || !io->random)
        return TB2_PROBE_CHECK_FAILED;
    memset(result, 0, sizeof(*result));
    if(input->kind != Tb2InputKeySecret && input->kind != Tb2InputKeyAes) {
        snprintf(
            result->error,
            sizeof(result->error),
            "No box key selected.\nChoose a secret or AES key file.");
        return TB2_PROBE_CHECK_FAILED;
    }
    Reader* reader = calloc(1, sizeof(*reader));
    if(!reader) {
        snprintf(result->error, sizeof(result->error), "Not enough RAM for read buffer.");
        return TB2_PROBE_IO_ERROR;
    }
    reader->io = io;
    reader->plain = reader->encrypted + 17;
    reader->result = result;
    reader->server_values = values;
    reader->server_records = records;
    configure_reader(reader);
    int rc = tb2_probe_crypto_begin();
    if(!rc) rc = inspect(reader, input);
    unmount(reader);
    if(reader->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(tb2_probe_crypto_current()) rc = TB2_PROBE_CHECK_FAILED;
    if(!rc)
        result->error[0] = '\0';
    else {
        memset(result->ca_sha256, 0, 32);
        memset(result->client_sha256, 0, 32);
    }
    if(rc && !result->error[0])
        snprintf(
            result->error,
            sizeof(result->error),
            "%s",
            rc == TB2_PROBE_IO_ERROR ?
                "SD read failed.\nCheck the card and retry." :
            rc == TB2_PROBE_CANCELLED ?
                "Operation stopped.\nYour selections were kept." :
                "Image check failed.\nOpen Details or Log for the exact step.");
    event(
        reader,
        "reader_finished",
        rc,
        rc     ? result->error :
        values ? "server preview; source unchanged; no files exported" :
                 "source unchanged; original and client backups verified; no new image");
    if(reader->io_failed) rc = TB2_PROBE_IO_ERROR;
    mbedtls_platform_zeroize(reader, sizeof(*reader));
    free(reader);
    return rc;
}

int tb2_reader_run_key(Tb2Reader* io, const Tb2InputKey* input, Tb2ReadResult* result) {
    return reader_run(io, input, result, NULL, NULL);
}
int tb2_reader_settings_identity(
    Tb2Reader* io,
    Tb2ReadResult* result,
    Tb2ImageIdentity* identity_out) {
    if(!io || !result || io->image_size != TB2_IMAGE_SIZE || !io->read || !io->event ||
       !io->cancelled || !io->progress)
        return TB2_PROBE_CHECK_FAILED;
    Tb2ImageIdentity identity;
    int rc = tb2_reader_identity(io, &identity);
    memset(result, 0, sizeof(*result));
    if(!rc && !identity.filesystem_known) rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) {
        result->offset = identity.offset;
        result->block_count = identity.block_count;
        result->disk_version = identity.disk_version;
        Reader* reader = calloc(1, sizeof(*reader));
        if(!reader)
            rc = TB2_PROBE_IO_ERROR;
        else {
            reader->io = io;
            reader->result = result;
            configure_reader(reader);
            rc = hash_source(reader, result->source_sha256);
            if(reader->io_failed) rc = TB2_PROBE_IO_ERROR;
            mbedtls_platform_zeroize(reader, sizeof(*reader));
            free(reader);
        }
    }
    if(rc && !result->error[0])
        snprintf(
            result->error,
            sizeof(result->error),
            "%s",
            rc == TB2_PROBE_CANCELLED ? "Operation stopped.\nYour selections were kept." :
            rc == TB2_PROBE_IO_ERROR  ? "SD read failed.\nCheck the card and retry." :
                                        "Settings filesystem is missing, ambiguous or damaged.");
    if(identity_out) {
        if(rc)
            memset(identity_out, 0, sizeof(*identity_out));
        else
            *identity_out = identity;
    }
    return rc;
}
int tb2_reader_settings(Tb2Reader* io, Tb2ReadResult* result) {
    return tb2_reader_settings_identity(io, result, NULL);
}
int tb2_reader_server_preview(
    Tb2Reader* io,
    const Tb2InputKey* input,
    Tb2ReadResult* result,
    Tb2ServerValues* values) {
    if(!values) return TB2_PROBE_CHECK_FAILED;
    memset(values, 0, sizeof(*values));
    int rc = reader_run(io, input, result, values, NULL);
    if(rc) memset(values, 0, sizeof(*values));
    return rc;
}

int tb2_reader_restore_source(
    Tb2Reader* io,
    const Tb2InputKey* input,
    Tb2ReadResult* result,
    Tb2ServerRecords* records) {
    if(records) memset(records, 0, sizeof(*records));
    int rc = reader_run(io, input, result, NULL, records);
    if(rc && records) memset(records, 0, sizeof(*records));
    return rc;
}

bool tb2_reader_parse_serial(const char* text, size_t size, uint8_t serial[TB2_SN_SIZE]) {
    while(size && (text[size - 1] == '\r' || text[size - 1] == '\n'))
        size--;
    if(size != 2 * TB2_SN_SIZE) return false;
    uint8_t parsed[TB2_SN_SIZE] = {0};
    for(size_t i = 0; i < size; i++) {
        char c = text[i];
        unsigned value;
        if(c >= '0' && c <= '9')
            value = c - '0';
        else if(c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if(c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            return false;
        parsed[i / 2] = (uint8_t)((parsed[i / 2] << 4) | value);
    }
    memcpy(serial, parsed, sizeof(parsed));
    mbedtls_platform_zeroize(parsed, sizeof(parsed));
    return true;
}

bool tb2_reader_parse_key(const char* text, size_t size, Tb2InputKey* input) {
    memset(input, 0, sizeof(*input));
    if(!text || size > TB2_KEY_TEXT_MAX) return false;
    if(size >= 3 && !memcmp(text, "\xef\xbb\xbf", 3)) {
        text += 3;
        size -= 3;
    }
    while(size && (text[size - 1] == '\r' || text[size - 1] == '\n'))
        size--;
    if(size != TB2_SN_SIZE * 2 && size != TB2_AES_KEY_SIZE * 2) return false;
    for(size_t i = 0; i < size; i++) {
        unsigned value;
        char c = text[i];
        if(c >= '0' && c <= '9')
            value = c - '0';
        else if(c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if(c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else {
            memset(input, 0, sizeof(*input));
            return false;
        }
        input->bytes[i / 2] = (uint8_t)((input->bytes[i / 2] << 4) | value);
    }
    input->kind = size == TB2_SN_SIZE * 2 ? Tb2InputKeySecret : Tb2InputKeyAes;
    return true;
}

int tb2_reader_derive_aes(
    Tb2Reader* io,
    const Tb2InputKey* input,
    unsigned profile,
    uint8_t key[TB2_AES_KEY_SIZE]) {
    memset(key, 0, TB2_AES_KEY_SIZE);
    if(input->kind == Tb2InputKeyAes && profile == 3) {
        memcpy(key, input->bytes, TB2_AES_KEY_SIZE);
        return 0;
    }
    if(input->kind != Tb2InputKeySecret || (profile != 1 && profile != 2))
        return TB2_PROBE_CHECK_FAILED;
    uint8_t salt[16], info[16];
    memcpy(salt, firmware_salt, sizeof(salt));
    memcpy(info, firmware_info, sizeof(info));
    if(profile == 2 && (!io->read(io->context, TB2_LEGACY_SALT_OFFSET, salt, sizeof(salt)) ||
                        !io->read(io->context, TB2_LEGACY_INFO_OFFSET, info, sizeof(info))))
        return TB2_PROBE_IO_ERROR;
    return mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt,
        sizeof(salt),
        input->bytes,
        TB2_SN_SIZE,
        info,
        sizeof(info),
        key,
        TB2_AES_KEY_SIZE);
}
