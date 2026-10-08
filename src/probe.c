#include "probe.h"
#include "tb2_config_select.h"

#include <lfs.h>
#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef union {
    size_t bytes;
    /* Cover the fundamental alignments used by this Mbed TLS configuration;
     * MSVC's C headers do not provide max_align_t. */
    long double alignment;
    void* pointer_alignment;
} AllocationHeader;

static size_t crypto_current;
static size_t crypto_peak;

size_t tb2_probe_crypto_peak(void) {
    return crypto_peak;
}
size_t tb2_probe_crypto_current(void) {
    return crypto_current;
}

static void* tracked_calloc(size_t count, size_t size) {
    if(count && size > (SIZE_MAX - sizeof(AllocationHeader)) / count) return NULL;
    size_t bytes = count * size + sizeof(AllocationHeader);
    AllocationHeader* header = calloc(1, bytes);
    if(!header) return NULL;
    header->bytes = bytes;
    crypto_current += bytes;
    if(crypto_current > crypto_peak) crypto_peak = crypto_current;
    return header + 1;
}

static void tracked_free(void* pointer) {
    if(!pointer) return;
    AllocationHeader* header = (AllocationHeader*)pointer - 1;
    crypto_current -= header->bytes;
    free(header);
}

int tb2_probe_crypto_begin(void) {
    if(crypto_current) return TB2_PROBE_CHECK_FAILED;
    crypto_peak = 0;
    return mbedtls_platform_set_calloc_free(tracked_calloc, tracked_free);
}

bool tb2_probe_range_valid(uint32_t offset, size_t size) {
    return offset <= TB2_PROBE_IMAGE_SIZE && size <= TB2_PROBE_IMAGE_SIZE - offset;
}

#ifndef TB2_CORE_MODULE
static int report(Tb2Probe* probe, const char* operation, int code) {
    char detail[192] = "ok";
    if(code < 0) mbedtls_strerror(code, detail, sizeof(detail));
    if(code > 0) snprintf(detail, sizeof(detail), "probe failure code=%d", code);
    if(!probe->event(probe->context, operation, code, detail)) return TB2_PROBE_IO_ERROR;
    return code;
}

static int boundary(Tb2Probe* probe, const char* stage) {
    probe->sample(probe->context, stage);
    if(probe->cancelled(probe->context)) return TB2_PROBE_CANCELLED;
    return report(probe, stage, 0);
}

/* RFC 5869 test case 1 and NIST SP 800-38A AES-128-CBC block 1. */
static int symmetric_test(Tb2Probe* probe) {
    static const uint8_t expected_hkdf[42] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
                                              0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
                                              0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
                                              0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
                                              0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    static const uint8_t key[16] = {
        0x2b,
        0x7e,
        0x15,
        0x16,
        0x28,
        0xae,
        0xd2,
        0xa6,
        0xab,
        0xf7,
        0x15,
        0x88,
        0x09,
        0xcf,
        0x4f,
        0x3c};
    static const uint8_t plain[16] = {
        0x6b,
        0xc1,
        0xbe,
        0xe2,
        0x2e,
        0x40,
        0x9f,
        0x96,
        0xe9,
        0x3d,
        0x7e,
        0x11,
        0x73,
        0x93,
        0x17,
        0x2a};
    static const uint8_t expected_aes[16] = {
        0x76,
        0x49,
        0xab,
        0xac,
        0x81,
        0x19,
        0xb2,
        0x46,
        0xce,
        0xe9,
        0x8e,
        0x9b,
        0x12,
        0xe9,
        0x19,
        0x7d};
    uint8_t ikm[22], salt[13], info[10], derived[42], iv[16], encoded[16], decoded[16];
    memset(ikm, 0x0b, sizeof(ikm));
    for(size_t i = 0; i < sizeof(salt); i++)
        salt[i] = (uint8_t)i;
    for(size_t i = 0; i < sizeof(info); i++)
        info[i] = (uint8_t)(0xf0 + i);
    int rc = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt,
        sizeof(salt),
        ikm,
        sizeof(ikm),
        info,
        sizeof(info),
        derived,
        sizeof(derived));
    if(!rc && memcmp(derived, expected_hkdf, sizeof(derived))) rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_platform_zeroize(derived, sizeof(derived));
    if(report(probe, "hkdf_rfc5869", rc)) return rc ? rc : TB2_PROBE_IO_ERROR;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    rc = mbedtls_aes_setkey_enc(&aes, key, 128);
    for(size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)i;
    if(!rc)
        rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(plain), iv, plain, encoded);
    if(!rc && memcmp(encoded, expected_aes, sizeof(encoded))) rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) rc = mbedtls_aes_setkey_dec(&aes, key, 128);
    for(size_t i = 0; i < sizeof(iv); i++)
        iv[i] = (uint8_t)i;
    if(!rc)
        rc = mbedtls_aes_crypt_cbc(
            &aes, MBEDTLS_AES_DECRYPT, sizeof(encoded), iv, encoded, decoded);
    if(!rc && memcmp(decoded, plain, sizeof(plain))) rc = TB2_PROBE_CHECK_FAILED;
    mbedtls_aes_free(&aes);
    return report(probe, "aes_nist_cbc", rc);
}

static int make_certificate(
    Tb2Probe* probe,
    mbedtls_pk_context* ca_key,
    mbedtls_pk_context* subject_key,
    mbedtls_md_type_t digest,
    bool is_ca,
    uint8_t* der,
    size_t capacity) {
    mbedtls_x509write_cert writer;
    mbedtls_x509write_crt_init(&writer);
    mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&writer, digest);
    mbedtls_x509write_crt_set_subject_key(&writer, subject_key);
    mbedtls_x509write_crt_set_issuer_key(&writer, ca_key);
    uint8_t serial[16];
    int rc = probe->random(probe->context, serial, sizeof(serial));
    if(!rc) serial[0] = (serial[0] & 0x7f) | 1;
    if(!rc) rc = mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof(serial));
    if(!rc)
        rc = mbedtls_x509write_crt_set_subject_name(
            &writer, is_ca ? "CN=TB2 SYNTHETIC PROBE CA" : "CN=tbs2.tonie.cloud");
    if(!rc) rc = mbedtls_x509write_crt_set_issuer_name(&writer, "CN=TB2 SYNTHETIC PROBE CA");
    if(!rc) rc = mbedtls_x509write_crt_set_validity(&writer, "20240101000000", "20340101000000");
    if(!rc) rc = mbedtls_x509write_crt_set_basic_constraints(&writer, is_ca, is_ca ? 0 : -1);
    if(!rc)
        rc = mbedtls_x509write_crt_set_key_usage(
            &writer,
            is_ca ? MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN :
                    MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if(!rc && !is_ca) {
        /* DER GeneralNames containing one DNS name; fixture only, not a SAN builder. */
        static const uint8_t san[] = "\x30\x12\x82\x10"
                                     "tbs2.tonie.cloud";
        rc = mbedtls_x509write_crt_set_extension(
            &writer, "\x55\x1d\x11", 3, 0, san, sizeof(san) - 1);
    }
    if(!rc) rc = mbedtls_x509write_crt_der(&writer, der, capacity, probe->random, probe->context);
    mbedtls_x509write_crt_free(&writer);
    return rc;
}

static int certificate_test(Tb2Probe* probe, mbedtls_ecp_group_id curve, const char* label) {
    int rc = 0;
    uint8_t* buffer = calloc(1, TB2_PROBE_BUFFER_SIZE);
    if(!buffer) return report(probe, "certificate_buffer_alloc", MBEDTLS_ERR_PK_ALLOC_FAILED);
    mbedtls_pk_context ca_key, leaf_key, imported;
    mbedtls_x509_crt ca, leaf;
    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&leaf_key);
    mbedtls_pk_init(&imported);
    mbedtls_x509_crt_init(&ca);
    mbedtls_x509_crt_init(&leaf);
    const mbedtls_pk_info_t* pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    mbedtls_md_type_t digest = curve == MBEDTLS_ECP_DP_SECP384R1 ? MBEDTLS_MD_SHA384 :
                                                                   MBEDTLS_MD_SHA256;
#define CHECK(operation, expression)             \
    do {                                         \
        rc = (expression);                       \
        rc = report(probe, operation, rc);       \
        if(rc) goto cleanup;                     \
        rc = boundary(probe, operation "_done"); \
        if(rc) goto cleanup;                     \
    } while(0)
    CHECK("ca_pk_setup", mbedtls_pk_setup(&ca_key, pk_info));
    CHECK(
        "ca_keygen",
        mbedtls_ecp_gen_key(curve, mbedtls_pk_ec(ca_key), probe->random, probe->context));
    CHECK("private_pem_export", mbedtls_pk_write_key_pem(&ca_key, buffer, TB2_PROBE_BUFFER_SIZE));
    CHECK(
        "private_pem_import",
        mbedtls_pk_parse_key(
            &imported, buffer, strlen((char*)buffer) + 1, NULL, 0, probe->random, probe->context));
    CHECK(
        "imported_key_match",
        mbedtls_pk_check_pair(&ca_key, &imported, probe->random, probe->context));
    mbedtls_pk_free(&imported);
    mbedtls_platform_zeroize(buffer, TB2_PROBE_BUFFER_SIZE);
    int length =
        make_certificate(probe, &ca_key, &ca_key, digest, true, buffer, TB2_PROBE_BUFFER_SIZE);
    if(length <= 0) {
        rc = report(probe, "ca_certificate_write", length ? length : TB2_PROBE_CHECK_FAILED);
        goto cleanup;
    }
    CHECK(
        "ca_certificate_parse",
        mbedtls_x509_crt_parse_der(&ca, buffer + TB2_PROBE_BUFFER_SIZE - length, (size_t)length));
    char name[48];
    snprintf(name, sizeof(name), "%s-ca.der", label);
    if(!probe->artifact(probe->context, name, ca.raw.p, ca.raw.len)) {
        rc = TB2_PROBE_IO_ERROR;
        goto cleanup;
    }
    CHECK("leaf_pk_setup", mbedtls_pk_setup(&leaf_key, pk_info));
    CHECK(
        "leaf_keygen",
        mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(leaf_key), probe->random, probe->context));
    length =
        make_certificate(probe, &ca_key, &leaf_key, digest, false, buffer, TB2_PROBE_BUFFER_SIZE);
    if(length <= 0) {
        rc = report(probe, "leaf_certificate_write", length ? length : TB2_PROBE_CHECK_FAILED);
        goto cleanup;
    }
    CHECK(
        "leaf_certificate_parse",
        mbedtls_x509_crt_parse_der(&leaf, buffer + TB2_PROBE_BUFFER_SIZE - length, (size_t)length));
    snprintf(name, sizeof(name), "%s-leaf.der", label);
    if(!probe->artifact(probe->context, name, leaf.raw.p, leaf.raw.len)) {
        rc = TB2_PROBE_IO_ERROR;
        goto cleanup;
    }
    uint32_t flags = 0;
    CHECK(
        "leaf_chain_hostname_verify",
        mbedtls_x509_crt_verify(&leaf, &ca, NULL, "tbs2.tonie.cloud", &flags, NULL, NULL));
    CHECK(
        "leaf_key_match",
        mbedtls_pk_check_pair(&leaf.pk, &leaf_key, probe->random, probe->context));
    rc = mbedtls_x509_crt_verify(&leaf, &ca, NULL, "wrong.invalid", &flags, NULL, NULL);
    if(rc != MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || !(flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)) {
        rc = report(probe, "wrong_hostname_not_rejected", TB2_PROBE_CHECK_FAILED);
        goto cleanup;
    }
    rc = report(probe, "wrong_hostname_rejected", 0);
cleanup:
    mbedtls_pk_free(&ca_key);
    mbedtls_pk_free(&leaf_key);
    mbedtls_pk_free(&imported);
    mbedtls_x509_crt_free(&ca);
    mbedtls_x509_crt_free(&leaf);
    mbedtls_platform_zeroize(buffer, TB2_PROBE_BUFFER_SIZE);
    free(buffer);
    return rc;
#undef CHECK
}

static bool lfs_address(lfs_block_t block, lfs_off_t off, lfs_size_t size, uint32_t* address) {
    if(block >= TB2_PROBE_BLOCK_COUNT || off > TB2_PROBE_BLOCK_SIZE ||
       size > TB2_PROBE_BLOCK_SIZE - off)
        return false;
    *address = block * TB2_PROBE_BLOCK_SIZE + off;
    return tb2_probe_range_valid(*address, size);
}

static int block_read(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    void* data,
    lfs_size_t size) {
    Tb2Probe* probe = cfg->context;
    uint32_t address;
    if(probe->cancelled(probe->context) || !lfs_address(block, off, size, &address))
        return LFS_ERR_IO;
    return probe->read(probe->context, address, data, size) ? 0 : LFS_ERR_IO;
}

static int block_write(
    const struct lfs_config* cfg,
    lfs_block_t block,
    lfs_off_t off,
    const void* data,
    lfs_size_t size) {
    Tb2Probe* probe = cfg->context;
    uint32_t address;
    if(probe->cancelled(probe->context) || !lfs_address(block, off, size, &address))
        return LFS_ERR_IO;
    return probe->write(probe->context, address, data, size) ? 0 : LFS_ERR_IO;
}

static int block_erase(const struct lfs_config* cfg, lfs_block_t block) {
    uint8_t erased[256];
    memset(erased, 0xff, sizeof(erased));
    for(lfs_off_t off = 0; off < TB2_PROBE_BLOCK_SIZE; off += sizeof(erased)) {
        int rc = block_write(cfg, block, off, erased, sizeof(erased));
        if(rc) return rc;
    }
    return 0;
}

static int block_sync(const struct lfs_config* cfg) {
    Tb2Probe* probe = cfg->context;
    return probe->sync(probe->context) ? 0 : LFS_ERR_IO;
}

static int lfs_report(Tb2Probe* probe, const char* operation, int rc) {
    const char* detail = rc == LFS_ERR_IO ?
                             "LittleFS backing-file I/O failed; see file operation" :
                         rc == LFS_ERR_CORRUPT ? "LittleFS metadata/content invalid" :
                         rc                    ? "LittleFS operation failed (native return code)" :
                                                 "ok";
    return probe->event(probe->context, operation, rc, detail) ? rc : TB2_PROBE_IO_ERROR;
}

static int filesystem_test(Tb2Probe* probe) {
    uint8_t cache_read[64], cache_prog[64], lookahead[64], file_cache[64];
    lfs_t lfs;
    struct lfs_config cfg = {
        .context = probe,
        .read = block_read,
        .prog = block_write,
        .erase = block_erase,
        .sync = block_sync,
        .read_size = 16,
        .prog_size = 16,
        .block_size = TB2_PROBE_BLOCK_SIZE,
        .block_count = TB2_PROBE_BLOCK_COUNT,
        .block_cycles = 500,
        .cache_size = 64,
        .lookahead_size = 64,
        .read_buffer = cache_read,
        .prog_buffer = cache_prog,
        .lookahead_buffer = lookahead,
        .disk_version = 0x00020000,
    };
    /* Formatting is allowed ONLY for this new synthetic scratch file. */
    int rc = lfs_report(probe, "lfs_format_synthetic_only", lfs_format(&lfs, &cfg));
    if(rc) return rc;
    cfg.block_count = 0; /* Exercise geometry recovery from the on-disk superblock. */
    rc = lfs_report(probe, "lfs_mount", lfs_mount(&lfs, &cfg));
    if(rc) return rc;
    struct lfs_fsinfo fsinfo = {0};
    rc = lfs_fs_stat(&lfs, &fsinfo);
    if(!rc && (fsinfo.block_count != TB2_PROBE_BLOCK_COUNT ||
               fsinfo.block_size != TB2_PROBE_BLOCK_SIZE || fsinfo.disk_version != 0x00020000))
        rc = LFS_ERR_CORRUPT;
    lfs_file_t file;
    struct lfs_file_config file_cfg = {.buffer = file_cache};
    bool opened = false;
    if(!rc) {
        rc = lfs_file_opencfg(&lfs, &file, "probe.txt", LFS_O_CREAT | LFS_O_WRONLY, &file_cfg);
        opened = !rc;
    }
    static const char payload[] = "TB2 synthetic resource probe; never a user dump";
    if(!rc) {
        lfs_ssize_t n = lfs_file_write(&lfs, &file, payload, sizeof(payload));
        if(n != sizeof(payload)) rc = n < 0 ? (int)n : LFS_ERR_IO;
    }
    if(opened) {
        int close_rc = lfs_file_close(&lfs, &file);
        if(!rc) rc = close_rc;
    }
    int unmount_rc = lfs_unmount(&lfs);
    if(!rc) rc = unmount_rc;
    rc = lfs_report(probe, "lfs_write_close_unmount", rc);
    if(rc) return rc;
    rc = lfs_report(probe, "lfs_remount", lfs_mount(&lfs, &cfg));
    if(rc) return rc;
    char readback[sizeof(payload)];
    rc = lfs_file_opencfg(&lfs, &file, "probe.txt", LFS_O_RDONLY, &file_cfg);
    opened = !rc;
    if(!rc) {
        lfs_ssize_t n = lfs_file_read(&lfs, &file, readback, sizeof(readback));
        if(n != sizeof(readback)) rc = n < 0 ? (int)n : LFS_ERR_IO;
    }
    if(!rc && memcmp(payload, readback, sizeof(payload))) rc = LFS_ERR_CORRUPT;
    if(opened) {
        int close_rc = lfs_file_close(&lfs, &file);
        if(!rc) rc = close_rc;
    }
    unmount_rc = lfs_unmount(&lfs);
    if(!rc) rc = unmount_rc;
    char detail[128];
    snprintf(
        detail,
        sizeof(detail),
        "block_size=%lu block_count=%lu disk=2.0 rc=%d",
        (unsigned long)cfg.block_size,
        (unsigned long)fsinfo.block_count,
        rc);
    if(!probe->event(probe->context, "littlefs_roundtrip", rc, detail)) return TB2_PROBE_IO_ERROR;
    return rc;
}

int tb2_probe_run(Tb2Probe* probe) {
    if(!probe || !probe->read || !probe->write || !probe->sync || !probe->event ||
       !probe->cancelled || !probe->random || !probe->artifact || !probe->sample)
        return TB2_PROBE_CHECK_FAILED;
    int rc = tb2_probe_crypto_begin();
    if(!rc) rc = boundary(probe, "symmetric_begin");
    if(!rc) rc = symmetric_test(probe);
    if(!rc) rc = boundary(probe, "p256_begin");
    if(!rc) rc = certificate_test(probe, MBEDTLS_ECP_DP_SECP256R1, "p256");
    if(!rc) rc = boundary(probe, "p384_begin");
    if(!rc) rc = certificate_test(probe, MBEDTLS_ECP_DP_SECP384R1, "p384");
    if(!rc) rc = boundary(probe, "littlefs_begin");
    if(!rc) rc = filesystem_test(probe);
    if(probe->cancelled(probe->context)) rc = TB2_PROBE_CANCELLED;
    if(crypto_current) rc = TB2_PROBE_CHECK_FAILED;
    probe->sample(probe->context, "finished");
    if(!probe->event(
           probe->context,
           "finished",
           rc,
           rc ? "NOT ACCEPTED" : "synthetic checks passed; hardware gate still requires review"))
        return TB2_PROBE_IO_ERROR;
    return rc;
}
#endif
