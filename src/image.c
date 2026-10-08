#include "image.h"
#include "probe.h"
#include "tb2_config_select.h"

#include <lfs.h>
#include <mbedtls/aes.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_CHUNK     2048U
#define IMAGE_CACHE     256U
#define IMAGE_PATH_MAX  256U
#define IMAGE_DEPTH_MAX 8U
#define CA_PATH         "/cert/ca.der.crypt"
#define SETTINGS_PATH   "/settings"
#define SETTINGS_TEMP   "/.tb2-settings"
static const char* const certificate_paths[] = {
    CA_PATH,
    "/cert/client.der.crypt",
    "/cert/private.der.crypt"};

typedef struct {
    Tb2Reader* source;
    Tb2ImageTarget* target;
    const Tb2ReadResult* inspected;
    Tb2ImageResult* result;
    const Tb2ServerChange* change;
    const Tb2SettingsPatch* patch;
    const Tb2CertificateRestore* restore;
    const char* certificate_path;
    unsigned certificate_index;
    uint8_t settings_hash[32];
    uint32_t settings_size;
    lfs_t fs;
    struct lfs_config cfg;
    bool output, mounted, io_failed, certificate_change;
    uint8_t read_cache[IMAGE_CACHE], prog_cache[IMAGE_CACHE], lookahead[16];
    uint8_t a[TB2_CRYPT_MAX], b[TB2_CRYPT_MAX];
    uint8_t key[TB2_AES_KEY_SIZE];
    char path[IMAGE_PATH_MAX];
} Image;

static int report(Image* image, const char* op, int rc, const char* detail) {
    if(!image->source->event(image->source->context, op, rc, detail)) {
        image->io_failed = true;
        return TB2_PROBE_IO_ERROR;
    }
    if(rc && !image->result->error[0]) {
        const char* message = !strcmp(op, "image_settings") ?
                                  "Image settings could not be updated safely." :
                              !strcmp(op, "image_settings_verify") ?
                                  "Image settings could not be verified." :
                              !strcmp(op, "image_copy") ?
                                  "The complete output image could not be created and verified." :
                              !strcmp(op, "image_outside_changed") ||
                                      !strcmp(op, "image_other_files_changed") ?
                                  "Image verification found changes outside the approved files." :
                                  detail;
        snprintf(image->result->error, sizeof(image->result->error), "%s", message);
    }
    return rc;
}

static int boundary(Image* image, const char* stage, uint32_t done, uint32_t total) {
    image->source->progress(image->source->context, stage, done, total);
    if(image->io_failed) return TB2_PROBE_IO_ERROR;
    return image->source->cancelled(image->source->context) ? TB2_PROBE_CANCELLED : 0;
}

static bool
    address(Image* image, lfs_block_t block, lfs_off_t off, lfs_size_t size, uint32_t* absolute) {
    if(block >= image->inspected->block_count || off > TB2_LFS_BLOCK_SIZE ||
       size > TB2_LFS_BLOCK_SIZE - off)
        return false;
    *absolute = image->inspected->offset + block * TB2_LFS_BLOCK_SIZE + off;
    return *absolute <= TB2_IMAGE_SIZE && size <= TB2_IMAGE_SIZE - *absolute;
}

static int image_read(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    void* data,
    lfs_size_t size) {
    Image* image = cfg->context;
    uint32_t absolute;
    if(!address(image, block, off, size, &absolute)) return LFS_ERR_CORRUPT;
    bool ok = image->output ? image->target->read(image->target->context, absolute, data, size) :
                              image->source->read(image->source->context, absolute, data, size);
    if(!ok) image->io_failed = true;
    return ok ? 0 : LFS_ERR_IO;
}

static int image_prog(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    const void* data,
    lfs_size_t size) {
    Image* image = cfg->context;
    uint32_t absolute;
    if(!image->output || !address(image, block, off, size, &absolute)) return LFS_ERR_IO;
    if(image->source->cancelled(image->source->context)) return LFS_ERR_IO;
    bool ok = image->target->write(image->target->context, absolute, data, size);
    if(!ok) image->io_failed = true;
    return ok ? 0 : LFS_ERR_IO;
}

static int image_erase(const struct lfs_config* cfg, lfs_block_t block) {
    uint8_t erased[IMAGE_CACHE];
    memset(erased, 0xff, sizeof(erased));
    for(uint32_t off = 0; off < TB2_LFS_BLOCK_SIZE; off += sizeof(erased)) {
        int rc = image_prog(cfg, block, off, erased, sizeof(erased));
        if(rc) return rc;
    }
    return 0;
}

static int image_sync(const struct lfs_config* cfg) {
    Image* image = cfg->context;
    if(!image->output) return 0;
    bool ok = image->target->sync(image->target->context);
    if(!ok) image->io_failed = true;
    return ok ? 0 : LFS_ERR_IO;
}

static void image_configure(Image* image) {
    image->cfg = (struct lfs_config){
        .context = image,
        .read = image_read,
        .prog = image_prog,
        .erase = image_erase,
        .sync = image_sync,
        .read_size = 16,
        .prog_size = 16,
        .block_size = TB2_LFS_BLOCK_SIZE,
        .block_count = image->inspected->block_count,
        .block_cycles = -1,
        .cache_size = IMAGE_CACHE,
        .lookahead_size = sizeof(image->lookahead),
        .read_buffer = image->read_cache,
        .prog_buffer = image->prog_cache,
        .lookahead_buffer = image->lookahead,
        .disk_version = image->inspected->disk_version};
}

static int mount(Image* image, bool output) {
    image->output = output;
    int rc = lfs_mount(&image->fs, &image->cfg);
    image->mounted = !rc;
    struct lfs_fsinfo info;
    if(!rc) rc = lfs_fs_stat(&image->fs, &info);
    if(!rc && (info.block_size != TB2_LFS_BLOCK_SIZE ||
               info.block_count != image->inspected->block_count ||
               info.disk_version != image->inspected->disk_version))
        rc = LFS_ERR_CORRUPT;
    return report(
        image, "image_mount", rc, output ? "output geometry/version" : "source geometry/version");
}

static int unmount(Image* image) {
    if(!image->mounted) return 0;
    image->mounted = false;
    return lfs_unmount(&image->fs);
}

/* Length-framed paths/type/size/content preserve directories and every file
 * except the one explicitly replaceable CA. LittleFS iteration order is stable
 * for unchanged names; any discrepancy is rejected, never silently ignored. */
static int tree(Image* image, mbedtls_sha256_context* hash, unsigned depth) {
    if(depth == IMAGE_DEPTH_MAX) return LFS_ERR_NAMETOOLONG;
    lfs_dir_t dir;
    int rc = lfs_dir_open(&image->fs, &dir, image->path[0] ? image->path : "/");
    if(rc) return rc;
    struct lfs_info info;
    size_t parent = strlen(image->path);
    while((rc = lfs_dir_read(&image->fs, &dir, &info)) > 0) {
        if(!strcmp(info.name, ".") || !strcmp(info.name, "..")) continue;
        rc = boundary(image, image->output ? "Comparing files" : "Scanning files", 0, 0);
        if(rc) break;
        size_t n = strlen(info.name);
        if(parent + 1 + n >= sizeof(image->path)) {
            rc = LFS_ERR_NAMETOOLONG;
            break;
        }
        image->path[parent] = '/';
        memcpy(image->path + parent + 1, info.name, n + 1);
        if((image->certificate_change && !strcmp(image->path, CA_PATH)) ||
           (image->restore && (!strcmp(image->path, certificate_paths[1]) ||
                               !strcmp(image->path, certificate_paths[2]))) ||
           ((image->patch || image->change || (image->restore && image->restore->connection)) &&
            !strcmp(image->path, SETTINGS_PATH))) {
            image->path[parent] = 0;
            continue;
        }
        uint8_t frame[7] = {
            (uint8_t)(parent + 1 + n),
            (uint8_t)((parent + 1 + n) >> 8),
            info.type,
            (uint8_t)info.size,
            (uint8_t)(info.size >> 8),
            (uint8_t)(info.size >> 16),
            (uint8_t)(info.size >> 24)};
        rc = mbedtls_sha256_update(hash, frame, sizeof(frame));
        if(!rc) rc = mbedtls_sha256_update(hash, (const uint8_t*)image->path, parent + 1 + n);
        if(!rc && info.type == LFS_TYPE_DIR)
            rc = tree(image, hash, depth + 1);
        else if(!rc && info.type == LFS_TYPE_REG) {
            lfs_file_t file;
            rc = lfs_file_open(&image->fs, &file, image->path, LFS_O_RDONLY);
            bool opened = !rc;
            for(uint32_t off = 0; !rc && off < info.size;) {
                size_t wanted = info.size - off < IMAGE_CHUNK ? info.size - off : IMAGE_CHUNK;
                lfs_ssize_t got = lfs_file_read(&image->fs, &file, image->a, wanted);
                if(got != (lfs_ssize_t)wanted) {
                    rc = got < 0 ? (int)got : LFS_ERR_IO;
                    break;
                }
                rc = mbedtls_sha256_update(hash, image->a, wanted);
                off += wanted;
                if(!rc) rc = boundary(image, "Checking file contents", off, info.size);
            }
            if(opened) {
                int closed = lfs_file_close(&image->fs, &file);
                if(!rc) rc = closed;
            }
        } else if(!rc)
            rc = LFS_ERR_INVAL;
        if(!rc) rc = report(image, "image_file_hash", 0, image->path);
        image->path[parent] = 0;
        if(rc) break;
    }
    image->path[parent] = 0;
    int closed = lfs_dir_close(&image->fs, &dir);
    return rc ? rc : closed;
}

static int tree_hash(Image* image, uint8_t digest[32]) {
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    image->path[0] = 0;
    if(!rc) rc = tree(image, &hash, 0);
    if(!rc) rc = mbedtls_sha256_finish(&hash, digest);
    mbedtls_sha256_free(&hash);
    return rc;
}

typedef struct {
    Image* image;
    lfs_file_t input, output;
    mbedtls_sha256_context hash;
    uint32_t size;
    bool writing;
} Settings;

static bool settings_read(void* context, uint32_t offset, void* bytes, size_t size) {
    Settings* settings = context;
    return lfs_file_seek(&settings->image->fs, &settings->input, offset, LFS_SEEK_SET) ==
               (lfs_soff_t)offset &&
           lfs_file_read(&settings->image->fs, &settings->input, bytes, size) == (lfs_ssize_t)size;
}
static bool settings_cancel(void* context) {
    Settings* s = context;
    return s->image->source->cancelled(s->image->source->context);
}
static bool settings_write(void* context, const void* bytes, size_t size) {
    Settings* s = context;
    if(size > TB2_SETTINGS_MAX - s->size || mbedtls_sha256_update(&s->hash, bytes, size))
        return false;
    s->size += (uint32_t)size;
    return !s->writing ||
           lfs_file_write(&s->image->fs, &s->output, bytes, size) == (lfs_ssize_t)size;
}

/** Preview hashes the complete expected byte stream; mutation writes a distinct
 * LittleFS file before replacement. A collision is never deleted or reused. */
static int settings_transform(Image* image, bool write) {
    Settings* s = calloc(1, sizeof(*s));
    if(!s) return TB2_PROBE_IO_ERROR;
    s->image = image;
    s->writing = write;
    mbedtls_sha256_init(&s->hash);
    int rc = mbedtls_sha256_starts(&s->hash, 0);
    bool input_open = false, output_open = false;
    if(!rc) {
        rc = lfs_file_open(&image->fs, &s->input, SETTINGS_PATH, LFS_O_RDONLY);
        input_open = !rc;
    }
    lfs_soff_t size = input_open ? lfs_file_size(&image->fs, &s->input) : 0;
    if(!rc && (size <= 0 || size > (lfs_soff_t)TB2_SETTINGS_MAX)) rc = LFS_ERR_CORRUPT;
    if(!rc && write) {
        rc = lfs_file_open(
            &image->fs, &s->output, SETTINGS_TEMP, LFS_O_WRONLY | LFS_O_CREAT | LFS_O_EXCL);
        output_open = !rc;
    }
    Tb2SettingsIO io = {
        .context = s,
        .size = (uint32_t)size,
        .read = settings_read,
        .write = settings_write,
        .cancelled = settings_cancel};
    Tb2ServerValues original = {0};
    Tb2SettingsSnapshot snapshot = {0};
    bool changed = false;
    if(!rc) {
        if(image->patch)
            rc = tb2_settings_transform(&io, image->patch, &snapshot, &changed);
        else
            rc = image->restore && image->restore->connection ?
                     tb2_server_restore(&io, image->restore->connection, &changed) :
                     tb2_server_transform(&io, image->change, &original, &changed);
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&s->hash, digest);
    if(!rc && write &&
       (s->size != image->settings_size || memcmp(digest, image->settings_hash, 32)))
        rc = TB2_PROBE_CHECK_FAILED;
    if(output_open) {
        int synced = lfs_file_sync(&image->fs, &s->output);
        int closed = lfs_file_close(&image->fs, &s->output);
        if(!rc) rc = synced ? synced : closed;
    }
    if(input_open) {
        int closed = lfs_file_close(&image->fs, &s->input);
        if(!rc) rc = closed;
    }
    if(!rc && write) rc = lfs_rename(&image->fs, SETTINGS_TEMP, SETTINGS_PATH);
    if(!rc && !write) {
        memcpy(image->settings_hash, digest, 32);
        image->settings_size = s->size;
        image->result->settings_changed = changed;
        Tb2ServerValues* endpoints = &image->result->endpoints;
        if(image->patch) {
            image->result->settings = snapshot;
            *endpoints = snapshot.servers;
            if(image->patch->server_fields & Tb2ServerOtaHost)
                strcpy(endpoints->https_host, image->patch->ota_host);
            if(image->patch->server_fields & Tb2ServerOtaPort)
                endpoints->https_port = image->patch->ota_port;
            if(image->patch->server_fields & Tb2ServerIciHost)
                strcpy(endpoints->mqtt_host, image->patch->ici_host);
            if(image->patch->server_fields & Tb2ServerIciPort)
                endpoints->mqtt_port = image->patch->ici_port;
        } else if(image->restore && image->restore->connection) {
            const Tb2ServerRecords* records = image->restore->connection;
            strcpy(endpoints->https_host, records->values[0]);
            endpoints->https_port = (uint16_t)strtoul(records->values[1], NULL, 10);
            strcpy(endpoints->mqtt_host, records->values[2]);
            endpoints->mqtt_port = (uint16_t)strtoul(records->values[3], NULL, 10);
        } else {
            *endpoints = original;
            if(image->change->fields & TB2_SERVER_HOST) {
                strcpy(endpoints->https_host, image->change->host);
                strcpy(endpoints->mqtt_host, image->change->host);
            }
            if(image->change->fields & TB2_SERVER_HTTPS)
                endpoints->https_port = tb2_server_port(image->change, false);
            if(image->change->fields & TB2_SERVER_MQTT)
                endpoints->mqtt_port = tb2_server_port(image->change, true);
        }
        image->result->endpoints_known =
            image->patch ? (snapshot.server_present & 0x0fU) == 0x0fU : true;
    }
    mbedtls_sha256_free(&s->hash);
    free(s);
    return report(image, "image_settings", rc, "explicit override; unknown bytes retained");
}

int tb2_image_settings_snapshot(
    Tb2Reader* source,
    const Tb2ReadResult* inspected,
    Tb2SettingsSnapshot* snapshot) {
    if(!source || !inspected || !snapshot || source->image_size != TB2_IMAGE_SIZE ||
       inspected->offset % TB2_LFS_BLOCK_SIZE || inspected->offset >= TB2_IMAGE_SIZE ||
       inspected->block_count < 2 ||
       inspected->block_count > (TB2_IMAGE_SIZE - inspected->offset) / TB2_LFS_BLOCK_SIZE)
        return TB2_PROBE_CHECK_FAILED;
    Image* image = calloc(1, sizeof(*image));
    if(!image) return TB2_PROBE_IO_ERROR;
    Tb2ImageResult result = {0};
    image->source = source;
    image->inspected = inspected;
    image->result = &result;
    image_configure(image);
    int rc = mount(image, false);
    Settings settings = {.image = image};
    bool opened = false;
    if(!rc) {
        rc = lfs_file_open(&image->fs, &settings.input, SETTINGS_PATH, LFS_O_RDONLY);
        opened = !rc;
    }
    lfs_soff_t size = opened ? lfs_file_size(&image->fs, &settings.input) : 0;
    if(!rc && (size <= 0 || size > (lfs_soff_t)TB2_SETTINGS_MAX)) rc = LFS_ERR_CORRUPT;
    Tb2SettingsIO io = {
        .context = &settings,
        .size = (uint32_t)size,
        .read = settings_read,
        .cancelled = settings_cancel};
    if(!rc) rc = tb2_settings_scan(&io, snapshot);
    if(opened) {
        int closed = lfs_file_close(&image->fs, &settings.input);
        if(!rc) rc = closed;
    }
    int closed = unmount(image);
    if(!rc) rc = closed;
    if(image->io_failed) rc = TB2_PROBE_IO_ERROR;
    mbedtls_platform_zeroize(image, sizeof(*image));
    free(image);
    return rc < 0 ? TB2_PROBE_CHECK_FAILED : rc;
}

static int settings_verify(Image* image) {
    lfs_file_t file;
    int rc = lfs_file_open(&image->fs, &file, SETTINGS_PATH, LFS_O_RDONLY);
    if(rc) return rc;
    if(lfs_file_size(&image->fs, &file) != (lfs_soff_t)image->settings_size) rc = LFS_ERR_CORRUPT;
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    if(!rc) rc = mbedtls_sha256_starts(&hash, 0);
    for(uint32_t offset = 0; !rc && offset < image->settings_size;) {
        size_t count = image->settings_size - offset;
        if(count > IMAGE_CHUNK) count = IMAGE_CHUNK;
        rc = boundary(image, "Checking settings", offset, image->settings_size);
        if(!rc && lfs_file_read(&image->fs, &file, image->a, count) != (lfs_ssize_t)count)
            rc = LFS_ERR_IO;
        if(!rc) rc = mbedtls_sha256_update(&hash, image->a, count);
        offset += count;
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&hash, digest);
    if(!rc && memcmp(digest, image->settings_hash, 32)) rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_sha256_free(&hash);
    int closed = lfs_file_close(&image->fs, &file);
    return report(
        image, "image_settings_verify", rc ? rc : closed, "complete expected settings bytes");
}

static int read_ca(Image* image, const uint8_t* expected, size_t size, bool* equal) {
    lfs_file_t file;
    int rc = lfs_file_open(&image->fs, &file, image->certificate_path, LFS_O_RDONLY);
    if(rc) return rc;
    lfs_ssize_t got = lfs_file_read(&image->fs, &file, image->a, sizeof(image->a));
    lfs_soff_t total = lfs_file_size(&image->fs, &file);
    int closed = lfs_file_close(&image->fs, &file);
    if(got < 33 || total != got || got > (lfs_ssize_t)TB2_CRYPT_MAX || (got - 17) % 16 ||
       image->a[0] < 1 || image->a[0] > 16)
        return LFS_ERR_CORRUPT;
    if(closed) return closed;
    uint8_t iv[16];
    memcpy(iv, image->a + 1, sizeof(iv));
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    rc = mbedtls_aes_setkey_dec(&aes, image->key, 128);
    if(!rc)
        rc = mbedtls_aes_crypt_cbc(
            &aes, MBEDTLS_AES_DECRYPT, got - 17, iv, image->a + 17, image->b);
    mbedtls_aes_free(&aes);
    size_t plain = (size_t)got - 17 - image->a[0];
    if(!plain || plain > TB2_PLAIN_MAX) rc = LFS_ERR_CORRUPT;
    for(size_t i = plain; !rc && i < (size_t)got - 17; i++)
        if(image->b[i]) rc = LFS_ERR_CORRUPT;
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    if(!rc && image->certificate_index < 2)
        rc = mbedtls_x509_crt_parse_der(&cert, image->b, plain);
    if(!rc && image->certificate_index < 2 && cert.raw.len != plain) rc = LFS_ERR_CORRUPT;
    *equal = !rc && plain == size && !memcmp(image->b, expected, size);
    mbedtls_x509_crt_free(&cert);
    return rc;
}

static int replace_ca(Image* image, const uint8_t* der, size_t size) {
    uint8_t iv[16];
    size_t pad = 16 - size % 16;
    memset(image->b, 0, size + pad);
    memcpy(image->b, der, size);
    image->a[0] = (uint8_t)pad;
    int rc = image->source->random(image->source->context, image->a + 1, 16);
    memcpy(iv, image->a + 1, sizeof(iv));
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if(!rc) rc = mbedtls_aes_setkey_enc(&aes, image->key, 128);
    if(!rc)
        rc = mbedtls_aes_crypt_cbc(
            &aes, MBEDTLS_AES_ENCRYPT, size + pad, iv, image->b, image->a + 17);
    mbedtls_aes_free(&aes);
    if(rc) return rc;
    lfs_file_t file;
    rc = lfs_file_open(&image->fs, &file, image->certificate_path, LFS_O_WRONLY | LFS_O_TRUNC);
    if(rc) return rc;
    lfs_ssize_t written = lfs_file_write(&image->fs, &file, image->a, size + pad + 17);
    if(written != (lfs_ssize_t)(size + pad + 17)) rc = written < 0 ? (int)written : LFS_ERR_IO;
    if(!rc) rc = lfs_file_sync(&image->fs, &file);
    int closed = lfs_file_close(&image->fs, &file);
    return rc ? rc : closed;
}

static int copy_source(Image* image) {
    if(!image->target->reset(image->target->context)) return TB2_PROBE_IO_ERROR;
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += IMAGE_CHUNK) {
        rc = boundary(image, "Copying original", off, TB2_IMAGE_SIZE);
        if(!rc && (!image->source->read(image->source->context, off, image->a, IMAGE_CHUNK) ||
                   !image->target->write(image->target->context, off, image->a, IMAGE_CHUNK)))
            rc = TB2_PROBE_IO_ERROR;
        if(!rc) rc = mbedtls_sha256_update(&hash, image->a, IMAGE_CHUNK);
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&hash, digest);
    mbedtls_sha256_free(&hash);
    if(!rc && memcmp(digest, image->inspected->source_sha256, sizeof(digest)))
        rc = TB2_PROBE_CHECK_FAILED;
    if(!rc && (!image->target->sync(image->target->context) ||
               image->target->size(image->target->context) != TB2_IMAGE_SIZE))
        rc = TB2_PROBE_IO_ERROR;
    return report(image, "image_copy", rc, "original fingerprint; exact 16 MiB; synced");
}

static int compare_bytes(Image* image) {
    if(image->target->size(image->target->context) != TB2_IMAGE_SIZE) return LFS_ERR_CORRUPT;
    mbedtls_sha256_context original, output;
    mbedtls_sha256_init(&original);
    mbedtls_sha256_init(&output);
    int rc = mbedtls_sha256_starts(&original, 0);
    if(!rc) rc = mbedtls_sha256_starts(&output, 0);
    uint32_t begin = image->inspected->offset;
    uint32_t end = begin + image->inspected->block_count * TB2_LFS_BLOCK_SIZE;
    for(uint32_t off = 0; !rc && off < TB2_IMAGE_SIZE; off += IMAGE_CHUNK) {
        rc = boundary(image, "Comparing image", off, TB2_IMAGE_SIZE);
        if(!rc && (!image->source->read(image->source->context, off, image->a, IMAGE_CHUNK) ||
                   !image->target->read(image->target->context, off, image->b, IMAGE_CHUNK)))
            rc = TB2_PROBE_IO_ERROR;
        if(!rc && (off < begin || off >= end) && memcmp(image->a, image->b, IMAGE_CHUNK)) {
            char detail[80];
            snprintf(
                detail,
                sizeof(detail),
                "byte mismatch outside LittleFS at 0x%08lx",
                (unsigned long)off);
            rc = report(image, "image_outside_changed", TB2_PROBE_CHECK_FAILED, detail);
        }
        if(!rc) rc = mbedtls_sha256_update(&original, image->a, IMAGE_CHUNK);
        if(!rc) rc = mbedtls_sha256_update(&output, image->b, IMAGE_CHUNK);
    }
    uint8_t digest[32];
    if(!rc) rc = mbedtls_sha256_finish(&original, digest);
    if(!rc && memcmp(digest, image->inspected->source_sha256, sizeof(digest)))
        rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) rc = mbedtls_sha256_finish(&output, image->result->sha256);
    mbedtls_sha256_free(&original);
    mbedtls_sha256_free(&output);
    return report(
        image,
        "image_byte_compare",
        rc,
        "source unchanged; outside-region bytes unchanged; output SHA256 captured");
}

static int image_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca,
    size_t ca_size,
    const Tb2ServerChange* change,
    const Tb2SettingsPatch* patch,
    const Tb2CertificateRestore* restore,
    Tb2ImageResult* result,
    bool build) {
    memset(result, 0, sizeof(*result));
    if(change && !tb2_server_change_valid(change)) return TB2_PROBE_CHECK_FAILED;
    if(patch && !tb2_settings_patch_valid(patch)) return TB2_PROBE_CHECK_FAILED;
    bool certificate_change = restore || (ca && ca_size);
    if(!source || !target || !inspected || !result || (!certificate_change && !patch) ||
       (certificate_change && !restore && (!ca || !ca_size || ca_size > TB2_PLAIN_MAX)) ||
       (restore && !restore->read) || (!certificate_change && (input || ca_size)) ||
       source->image_size != TB2_IMAGE_SIZE || inspected->offset % TB2_LFS_BLOCK_SIZE ||
       inspected->offset >= TB2_IMAGE_SIZE || inspected->block_count < 2 ||
       inspected->block_count > (TB2_IMAGE_SIZE - inspected->offset) / TB2_LFS_BLOCK_SIZE) {
        snprintf(result->error, sizeof(result->error), "Invalid CA size or LittleFS bounds.");
        return TB2_PROBE_CHECK_FAILED;
    }
    Image* image = calloc(1, sizeof(*image));
    if(!image) return TB2_PROBE_IO_ERROR;
    image->source = source;
    image->target = target;
    image->inspected = inspected;
    image->result = result;
    image->change = change && change->fields ? change : NULL;
    image->patch = patch;
    image->restore = restore;
    image->certificate_change = certificate_change;
    image->certificate_path = CA_PATH;
    image_configure(image);
    uint8_t* plain = restore ? malloc(TB2_PLAIN_MAX) : NULL;
    int rc = restore && !plain ? TB2_PROBE_IO_ERROR : tb2_probe_crypto_begin();
    if(!rc && restore) {
        if(!restore->read(restore->context, 0, plain, TB2_PLAIN_MAX, &ca_size) || !ca_size ||
           ca_size > TB2_PLAIN_MAX)
            rc = TB2_PROBE_CHECK_FAILED;
        ca = plain;
    }
    if(!rc && certificate_change)
        rc = tb2_reader_derive_aes(source, input, inspected->profile, image->key);
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    if(!rc && certificate_change) rc = mbedtls_x509_crt_parse_der(&cert, ca, ca_size);
    if(!rc && certificate_change && cert.raw.len != ca_size) rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_x509_crt_free(&cert);
    uint8_t original_tree[32], output_tree[32];
    bool equal = false;
    if(!rc) rc = mount(image, false);
    if(!rc && certificate_change) rc = read_ca(image, ca, ca_size, &equal);
    result->ca_changed = certificate_change && !equal;
    bool settings = image->patch || image->change || (restore && restore->connection);
    if(!rc && settings) rc = settings_transform(image, false);
    if(!rc) rc = tree_hash(image, original_tree);
    int closed = unmount(image);
    if(!rc) rc = closed;
    if(!rc && build) rc = copy_source(image);
    if(!rc) rc = mount(image, true);
    if(!rc && build && certificate_change && !equal) rc = replace_ca(image, ca, ca_size);
    for(unsigned i = 1; !rc && restore && build && i < 3; i++) {
        size_t size = 0;
        image->certificate_index = i;
        image->certificate_path = certificate_paths[i];
        if(!restore->read(restore->context, i, plain, TB2_PLAIN_MAX, &size) || !size ||
           size > TB2_PLAIN_MAX)
            rc = TB2_PROBE_CHECK_FAILED;
        bool same = false;
        if(!rc) rc = read_ca(image, plain, size, &same);
        if(!rc && !same) rc = replace_ca(image, plain, size);
    }
    if(!rc && build && result->settings_changed) rc = settings_transform(image, true);
    closed = unmount(image);
    if(!rc) rc = closed;
    if(!rc && build && !target->sync(target->context)) rc = TB2_PROBE_IO_ERROR;
    /* Discard all LittleFS caches before verifying the on-SD representation. */
    if(!rc) rc = mount(image, true);
    for(unsigned i = 0; !rc && certificate_change && i < (restore ? 3U : 1U); i++) {
        image->certificate_index = i;
        image->certificate_path = certificate_paths[i];
        size_t size = ca_size;
        if(restore && (!restore->read(restore->context, i, plain, TB2_PLAIN_MAX, &size) || !size ||
                       size > TB2_PLAIN_MAX))
            rc = TB2_PROBE_CHECK_FAILED;
        if(!rc) rc = read_ca(image, restore ? plain : ca, size, &equal);
        if(!rc && !equal) rc = TB2_PROBE_CHECK_FAILED;
    }
    if(!rc && settings) rc = settings_verify(image);
    if(!rc) rc = tree_hash(image, output_tree);
    if(!rc && memcmp(original_tree, output_tree, sizeof(original_tree)))
        rc = report(
            image,
            "image_other_files_changed",
            TB2_PROBE_CHECK_FAILED,
            "unrelated paths/type/size/content differ");
    closed = unmount(image);
    if(!rc) rc = closed;
    if(!rc) rc = compare_bytes(image);
    if(image->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(source->cancelled(source->context)) rc = TB2_PROBE_CANCELLED;
    if(tb2_probe_crypto_current()) rc = TB2_PROBE_CHECK_FAILED;
    rc = report(
        image,
        "image_finished",
        rc,
        rc ? "Result NOT released; original unchanged" :
             "Allowed certificate files compared; unrelated files and outside bytes unchanged");
    if(plain) mbedtls_platform_zeroize(plain, TB2_PLAIN_MAX);
    free(plain);
    mbedtls_platform_zeroize(image, sizeof(*image));
    free(image);
    return rc;
}

int tb2_image_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca,
    size_t size,
    const Tb2ServerChange* change,
    Tb2ImageResult* result,
    bool build) {
    return image_process(
        source, target, input, inspected, ca, size, change, NULL, NULL, result, build);
}
int tb2_image_settings_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2ReadResult* inspected,
    const Tb2SettingsPatch* patch,
    Tb2ImageResult* result,
    bool build) {
    return image_process(
        source, target, NULL, inspected, NULL, 0, NULL, patch, NULL, result, build);
}
int tb2_image_settings_cert_process(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca,
    size_t size,
    const Tb2SettingsPatch* patch,
    Tb2ImageResult* result,
    bool build) {
    return image_process(
        source, target, input, inspected, ca, size, NULL, patch, NULL, result, build);
}
int tb2_image_restore(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const Tb2CertificateRestore* restore,
    Tb2ImageResult* result,
    bool build) {
    if(!restore) return TB2_PROBE_CHECK_FAILED;
    return image_process(
        source, target, input, inspected, NULL, 0, NULL, NULL, restore, result, build);
}

int tb2_image_build(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca,
    size_t ca_size,
    Tb2ImageResult* result) {
    return tb2_image_process(source, target, input, inspected, ca, ca_size, NULL, result, true);
}

int tb2_image_verify(
    Tb2Reader* source,
    Tb2ImageTarget* target,
    const Tb2InputKey* input,
    const Tb2ReadResult* inspected,
    const uint8_t* ca,
    size_t ca_size,
    Tb2ImageResult* result) {
    return tb2_image_process(source, target, input, inspected, ca, ca_size, NULL, result, false);
}
