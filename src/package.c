#include "package.h"
#include "probe.h"
#include "tb2_config_select.h"
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* const tb2_package_names[TB2_PACKAGE_FILES] = TB2_PACKAGE_FILENAMES;
#define GENERATED_PEM_CAPACITY  2048U
#define PUBLIC_KEY_DER_CAPACITY 160U

typedef struct {
    Tb2PackageIO* io;
    const Tb2PackageOptions* options;
    Tb2PackageResult* result;
    uint8_t* bytes;
    size_t capacity;
    bool io_failed;
    bool allow_reissue;
    bool historical;
} Package;

static void release_buffer(Package* p) {
    if(p->bytes) {
        mbedtls_platform_zeroize(p->bytes, p->capacity);
        free(p->bytes);
    }
    p->bytes = NULL;
    p->capacity = 0;
}
static bool buffer(Package* p, size_t size) {
    release_buffer(p);
    p->bytes = calloc(1, size);
    if(p->bytes) p->capacity = size;
    return p->bytes != NULL;
}

static int event(Package* p, const char* op, int rc, const char* detail) {
    if(!p->io->event(p->io->context, op, rc, detail)) {
        p->io_failed = true;
        return TB2_PROBE_IO_ERROR;
    }
    return rc;
}
static int error(Package* p, int rc, const char* file, const char* message) {
    snprintf(p->result->error, sizeof(p->result->error), "%s: %s", file, message);
    return event(p, "package_error", rc, p->result->error);
}
static int boundary(Package* p, const char* detail) {
    if(p->io_failed) return TB2_PROBE_IO_ERROR;
    if(p->io->cancelled(p->io->context)) return TB2_PROBE_CANCELLED;
    return event(p, "package_step", 0, detail);
}
static bool date_valid(const char* date) {
    if(date[14]) return false;
    for(unsigned i = 0; i < 14; i++)
        if(date[i] < '0' || date[i] > '9') return false;
    unsigned year = 0;
    for(unsigned i = 0; i < 4; i++)
        year = year * 10U + (unsigned)(date[i] - '0');
    unsigned month = (unsigned)(date[4] - '0') * 10U + (unsigned)(date[5] - '0');
    unsigned day = (unsigned)(date[6] - '0') * 10U + (unsigned)(date[7] - '0');
    static const uint8_t days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if(year < 2024 || year > 2099 || !month || month > 12 || !day) return false;
    unsigned limit =
        days[month - 1] + (month == 2 && year % 4U == 0 && (year % 100U != 0 || year % 400U == 0));
    return day <= limit && (unsigned)(date[8] - '0') * 10U + (unsigned)(date[9] - '0') < 24U &&
           (unsigned)(date[10] - '0') * 10U + (unsigned)(date[11] - '0') < 60U &&
           (unsigned)(date[12] - '0') * 10U + (unsigned)(date[13] - '0') < 60U;
}
/* Require one complete object, not a valid DER/PEM prefix followed by garbage. */
static bool complete_object(Package* p, size_t* size, bool* pem) {
    size_t start = 0;
    if(*size >= 3 && !memcmp(p->bytes, "\xef\xbb\xbf", 3)) start = 3;
    while(start < *size && (p->bytes[start] == ' ' || p->bytes[start] == '\r' ||
                            p->bytes[start] == '\n' || p->bytes[start] == '\t'))
        start++;
    if(start) {
        *size -= start;
        memmove(p->bytes, p->bytes + start, *size);
    }
    p->bytes[*size] = 0;
    *pem = *size >= 11 && !memcmp(p->bytes, "-----BEGIN ", 11);
    if(*pem) {
        if(memchr(p->bytes, 0, *size)) return false;
        char* end = strstr((char*)p->bytes, "-----END ");
        if(!end) return false;
        end = strstr(end + 9, "-----");
        if(!end) return false;
        end += 5;
        while(*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t')
            end++;
        return !*end;
    }
    unsigned char* cursor = p->bytes;
    size_t length;
    return !mbedtls_asn1_get_tag(
               &cursor,
               p->bytes + *size,
               &length,
               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) &&
           length == (size_t)(p->bytes + *size - cursor);
}
static bool curve_ok(mbedtls_pk_context* key) {
    if(!mbedtls_pk_can_do(key, MBEDTLS_PK_ECDSA)) return false;
    size_t bits = mbedtls_pk_get_bitlen(key);
    return bits == 256 || bits == 384;
}
static int read_file(Package* p, unsigned index, size_t* size) {
    release_buffer(p);
    int rc = p->io->read(p->io->context, tb2_package_names[index], NULL, 0, size);
    if(rc == TB2_PACKAGE_MISSING) {
        p->result->missing |= 1U << index;
        return rc;
    }
    if(rc) return error(p, rc, tb2_package_names[index], "Cannot read complete file");
    if(!*size || *size > TB2_PACKAGE_FILE_MAX)
        return error(
            p, TB2_PROBE_CHECK_FAILED, tb2_package_names[index], "File empty or too large");
    if(!buffer(p, *size + 1))
        return error(p, TB2_PROBE_IO_ERROR, tb2_package_names[index], "Not enough RAM for file");
    size_t expected = *size;
    rc = p->io->read(p->io->context, tb2_package_names[index], p->bytes, expected, size);
    if(rc || *size != expected)
        return error(
            p, TB2_PROBE_IO_ERROR, tb2_package_names[index], "File changed or incomplete read");
    return event(p, "package_read", 0, tb2_package_names[index]);
}
static int cert_dates(Package* p, mbedtls_x509_crt* cert, const char* file) {
    char from[32], to[32], detail[128];
    snprintf(
        from,
        sizeof(from),
        "%04d%02d%02d%02d%02d%02d",
        cert->valid_from.year,
        cert->valid_from.mon,
        cert->valid_from.day,
        cert->valid_from.hour,
        cert->valid_from.min,
        cert->valid_from.sec);
    snprintf(
        to,
        sizeof(to),
        "%04d%02d%02d%02d%02d%02d",
        cert->valid_to.year,
        cert->valid_to.mon,
        cert->valid_to.day,
        cert->valid_to.hour,
        cert->valid_to.min,
        cert->valid_to.sec);
    snprintf(
        detail,
        sizeof(detail),
        "%s validity=%s..%s confirmed_now=%s",
        file,
        from,
        to,
        p->options->now);
    int rc = strcmp(p->options->now, from) < 0 || strcmp(p->options->now, to) > 0 ?
                 TB2_PROBE_CHECK_FAILED :
                 0;
    if(event(p, "package_validity", rc, detail) == TB2_PROBE_IO_ERROR) return TB2_PROBE_IO_ERROR;
    if(rc && p->historical) {
        p->result->validity |= strcmp(p->options->now, from) < 0 ? 2U : 1U;
        return 0;
    }
    if(rc)
        return error(
            p,
            rc,
            file,
            strcmp(p->options->now, from) < 0 ? "Not yet valid; check date" :
                                                "Expired; no automatic renewal");
    return 0;
}
static int parse_cert(Package* p, unsigned index, mbedtls_x509_crt* cert) {
    size_t size = 0;
    int rc = read_file(p, index, &size);
    if(rc) return rc;
    bool pem;
    if(!complete_object(p, &size, &pem))
        return error(
            p, TB2_PROBE_CHECK_FAILED, tb2_package_names[index], "Incomplete or ambiguous PEM/DER");
    rc = pem ? mbedtls_x509_crt_parse(cert, p->bytes, size + 1) :
               mbedtls_x509_crt_parse_der(cert, p->bytes, size);
    release_buffer(p); /* Parser owns its DER copy; do not keep a duplicate. */
    if(rc || cert->next || !curve_ok(&cert->pk))
        return error(
            p,
            rc ? rc : TB2_PROBE_CHECK_FAILED,
            tb2_package_names[index],
            "Invalid certificate; one P-256/P-384 certificate required");
    rc = cert_dates(p, cert, tb2_package_names[index]);
    if(rc) return rc;
    uint8_t digest[32];
    char hex[65], detail[128];
    rc = mbedtls_sha256(cert->raw.p, cert->raw.len, digest, 0);
    if(rc) return rc;
    for(unsigned i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    snprintf(
        detail,
        sizeof(detail),
        "%s EC-%lu cert_sha256=%s",
        tb2_package_names[index],
        (unsigned long)mbedtls_pk_get_bitlen(&cert->pk),
        hex);
    return event(p, "package_public_certificate", 0, detail);
}
static int parse_key(Package* p, unsigned index, mbedtls_pk_context* key) {
    size_t size = 0;
    int rc = read_file(p, index, &size);
    if(rc) return rc;
    bool pem;
    if(!complete_object(p, &size, &pem))
        return error(
            p,
            TB2_PROBE_CHECK_FAILED,
            tb2_package_names[index],
            "Incomplete or ambiguous PEM/DER key");
    rc = mbedtls_pk_parse_key(
        key, p->bytes, size + (pem ? 1 : 0), NULL, 0, p->io->random, p->io->context);
    release_buffer(p);
    if(rc || !curve_ok(key))
        return error(
            p,
            rc ? rc : TB2_PROBE_CHECK_FAILED,
            tb2_package_names[index],
            "Invalid key; unencrypted P-256/P-384 required");
    return 0;
}
static void hex_digest(const uint8_t digest[32], char text[65]) {
    for(unsigned i = 0; i < 32; i++)
        snprintf(text + 2 * i, 3, "%02x", digest[i]);
}
static int public_hash(mbedtls_pk_context* key, char text[65]) {
    uint8_t bytes[PUBLIC_KEY_DER_CAPACITY];
    int size = mbedtls_pk_write_pubkey_der(key, bytes, sizeof(bytes));
    if(size <= 0) return size ? size : TB2_PROBE_CHECK_FAILED;
    uint8_t digest[32];
    int rc = mbedtls_sha256(bytes + sizeof(bytes) - size, size, digest, 0);
    if(!rc) hex_digest(digest, text);
    return rc;
}
static int pair(Package* p, unsigned index, mbedtls_x509_crt* cert, mbedtls_pk_context* key) {
    int rc = mbedtls_pk_check_pair(&cert->pk, key, p->io->random, p->io->context);
    if(rc) {
        char cert_hash[65] = "unavailable", key_hash[65] = "unavailable";
        public_hash(&cert->pk, cert_hash);
        public_hash(key, key_hash);
        snprintf(
            p->result->error,
            sizeof(p->result->error),
            "%s does not match %s. Public SHA256: %s / %s",
            tb2_package_names[index + 1],
            tb2_package_names[index],
            key_hash,
            cert_hash);
        return event(p, "package_key_mismatch", rc, p->result->error);
    }
    return event(p, "package_key_pair", 0, tb2_package_names[index]);
}
static int save(Package* p, const char* name, const void* data, size_t size) {
    if(!p->io->save(p->io->context, name, data, size))
        return error(p, TB2_PROBE_IO_ERROR, name, "Save, sync or readback failed");
    return event(p, "package_saved_verified", 0, name);
}
static int generate_key(Package* p, unsigned index, mbedtls_pk_context* key) {
    int rc = boundary(p, "Generating P-256 key; stop at next safe boundary");
    if(!rc) rc = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if(!rc)
        rc = mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key), p->io->random, p->io->context);
    if(!rc && !buffer(p, GENERATED_PEM_CAPACITY)) rc = TB2_PROBE_IO_ERROR;
    if(!rc) rc = mbedtls_pk_write_key_pem(key, p->bytes, p->capacity);
    if(!rc) rc = save(p, tb2_package_names[index], p->bytes, strlen((char*)p->bytes));
    release_buffer(p);
    if(!rc) p->result->generated |= 1U << index;
    return rc;
}
static int
    append_san(mbedtls_x509write_cert* writer, const mbedtls_x509_crt* old, const char* host) {
    uint8_t* buffer = malloc(TB2_PACKAGE_FILE_MAX);
    if(!buffer) return TB2_PROBE_IO_ERROR;
    uint8_t* cursor = buffer + TB2_PACKAGE_FILE_MAX;
    size_t length = 0;
    int rc = 0;
    for(const mbedtls_x509_sequence* san = &old->subject_alt_names; !rc && san && san->buf.p;
        san = san->next) {
        int n = mbedtls_asn1_write_raw_buffer(&cursor, buffer, san->buf.p, san->buf.len);
        if(n >= 0)
            length += n;
        else
            rc = n;
        if(!rc) {
            n = mbedtls_asn1_write_len(&cursor, buffer, san->buf.len);
            if(n >= 0)
                length += n;
            else
                rc = n;
        }
        if(!rc) {
            n = mbedtls_asn1_write_tag(&cursor, buffer, (unsigned char)san->buf.tag);
            if(n >= 0)
                length += n;
            else
                rc = n;
        }
    }
    size_t size = strlen(host);
    int n = rc ? rc : mbedtls_asn1_write_raw_buffer(&cursor, buffer, (const uint8_t*)host, size);
    if(n >= 0)
        length += n;
    else
        rc = n;
    if(!rc) {
        n = mbedtls_asn1_write_len(&cursor, buffer, size);
        if(n >= 0)
            length += n;
        else
            rc = n;
    }
    if(!rc) {
        n = mbedtls_asn1_write_tag(
            &cursor, buffer, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME);
        if(n >= 0)
            length += n;
        else
            rc = n;
    }
    if(!rc) {
        n = mbedtls_asn1_write_len(&cursor, buffer, length);
        if(n >= 0)
            length += n;
        else
            rc = n;
    }
    if(!rc) {
        n = mbedtls_asn1_write_tag(
            &cursor, buffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if(n >= 0)
            length += n;
        else
            rc = n;
    }
    if(!rc)
        rc = mbedtls_x509write_crt_set_extension(
            writer,
            MBEDTLS_OID_SUBJECT_ALT_NAME,
            MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
            0,
            cursor,
            length);
    free(buffer);
    return rc;
}
static bool cert_time(char out[TB2_DATE_SIZE], const mbedtls_x509_time* time) {
    char text[32];
    int count = snprintf(
        text,
        sizeof(text),
        "%04d%02d%02d%02d%02d%02d",
        time->year,
        time->mon,
        time->day,
        time->hour,
        time->min,
        time->sec);
    if(count != TB2_DATE_SIZE - 1) return false;
    memcpy(out, text, TB2_DATE_SIZE);
    return date_valid(out);
}
static int issue(
    Package* p,
    unsigned index,
    mbedtls_x509_crt* ca,
    mbedtls_pk_context* ca_key,
    mbedtls_x509_crt* cert,
    mbedtls_pk_context* key,
    const char* host) {
    int rc = boundary(p, "Signing certificate; keeping existing key");
    mbedtls_x509write_cert writer;
    mbedtls_x509write_crt_init(&writer);
    mbedtls_x509write_crt_set_version(&writer, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(
        &writer, mbedtls_pk_get_bitlen(ca_key) == 384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&writer, key);
    mbedtls_x509write_crt_set_issuer_key(&writer, ca_key);
    uint8_t serial[16] = {0};
    if(!rc) rc = p->io->random(p->io->context, serial, sizeof(serial));
    serial[0] = (serial[0] & 0x7f) | 1;
    if(!rc) rc = mbedtls_x509write_crt_set_serial_raw(&writer, serial, sizeof(serial));
    char subject[TB2_HOST_MAX + 4], issuer[256];
    snprintf(subject, sizeof(subject), "CN=%s", host ? host : "TB2 local CA");
    if(!host)
        snprintf(issuer, sizeof(issuer), "%s", subject);
    else if(!rc && mbedtls_x509_dn_gets(issuer, sizeof(issuer), &ca->subject) < 0)
        rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) rc = mbedtls_x509write_crt_set_subject_name(&writer, subject);
    if(!rc) rc = mbedtls_x509write_crt_set_issuer_name(&writer, issuer);
    bool reissue = cert->raw.p != NULL;
    char first[TB2_DATE_SIZE], last[TB2_DATE_SIZE];
    if(reissue && (!cert_time(first, &cert->valid_from) || !cert_time(last, &cert->valid_to)))
        rc = TB2_PROBE_CHECK_FAILED;
    if(!rc)
        rc = mbedtls_x509write_crt_set_validity(
            &writer, reissue ? first : p->options->now, reissue ? last : p->options->expires);
    if(!rc) rc = mbedtls_x509write_crt_set_basic_constraints(&writer, !host, host ? -1 : 0);
    if(!rc)
        rc = mbedtls_x509write_crt_set_key_usage(
            &writer,
            host ? MBEDTLS_X509_KU_DIGITAL_SIGNATURE :
                   MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    if(!rc && host) {
        mbedtls_x509_san_list san = {
            .node = {
                .type = MBEDTLS_X509_SAN_DNS_NAME,
                .san = {.unstructured_name = {.p = (unsigned char*)host, .len = strlen(host)}}}};
        rc = reissue ? append_san(&writer, cert, host) :
                       mbedtls_x509write_crt_set_subject_alternative_name(&writer, &san);
        const uint8_t eku[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
        if(!rc)
            rc = mbedtls_x509write_crt_set_extension(
                &writer,
                MBEDTLS_OID_EXTENDED_KEY_USAGE,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                0,
                eku,
                sizeof(eku));
    }
    if(!rc && !buffer(p, GENERATED_PEM_CAPACITY)) rc = TB2_PROBE_IO_ERROR;
    if(!rc)
        rc = mbedtls_x509write_crt_pem(
            &writer, p->bytes, p->capacity, p->io->random, p->io->context);
    mbedtls_x509write_crt_free(&writer);
    if(!rc) rc = save(p, tb2_package_names[index], p->bytes, strlen((char*)p->bytes));
    if(!rc) {
        mbedtls_x509_crt_free(cert);
        mbedtls_x509_crt_init(cert);
        rc = parse_cert(p, index, cert);
    }
    if(!rc) p->result->generated |= 1U << index;
    return rc;
}
static int root_check(Package* p, mbedtls_x509_crt* ca) {
    if(ca->issuer_raw.len != ca->subject_raw.len ||
       memcmp(ca->issuer_raw.p, ca->subject_raw.p, ca->subject_raw.len))
        return error(
            p,
            TB2_PROBE_CHECK_FAILED,
            tb2_package_names[0],
            "Self-signed root CA required; no intermediate CA");
    if(ca->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 &&
       ca->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA384)
        return error(
            p, TB2_PROBE_CHECK_FAILED, tb2_package_names[0], "Only SHA-256/SHA-384 supported");
    uint8_t digest[48];
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(ca->MBEDTLS_PRIVATE(sig_md));
    int rc = mbedtls_md(md, ca->tbs.p, ca->tbs.len, digest);
    if(!rc)
        rc = mbedtls_pk_verify_ext(
            ca->MBEDTLS_PRIVATE(sig_pk),
            ca->MBEDTLS_PRIVATE(sig_opts),
            &ca->pk,
            ca->MBEDTLS_PRIVATE(sig_md),
            digest,
            mbedtls_md_get_size(md),
            ca->MBEDTLS_PRIVATE(sig).p,
            ca->MBEDTLS_PRIVATE(sig).len);
    if(!rc && (ca->MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) &&
       !ca->MBEDTLS_PRIVATE(ca_istrue))
        rc = TB2_PROBE_CHECK_FAILED;
    if(!rc) rc = mbedtls_x509_crt_check_key_usage(ca, MBEDTLS_X509_KU_KEY_CERT_SIGN);
    if(rc) return error(p, rc, tb2_package_names[0], "Invalid CA signature or CA key usage");
    if(!(ca->MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS))
        event(
            p,
            "package_legacy_root",
            0,
            "explicitly imported root without BasicConstraints; retained unchanged");
    return mbedtls_sha256(ca->raw.p, ca->raw.len, p->result->ca_sha256, 0);
}
static int leaf_check(
    Package* p,
    unsigned index,
    mbedtls_x509_crt* leaf,
    mbedtls_x509_crt* ca,
    const char* host) {
    uint32_t flags = 0;
    char first[TB2_HOST_MAX] = "no DNS SAN";
    bool seen = false;
    for(const mbedtls_x509_sequence* san = &leaf->subject_alt_names; san && san->buf.p;
        san = san->next) {
        if(san->buf.tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME)) continue;
        char name[TB2_HOST_MAX];
        size_t n = san->buf.len < sizeof(name) - 1 ? san->buf.len : sizeof(name) - 1;
        for(size_t i = 0; i < n; i++)
            name[i] = san->buf.p[i] >= 32 && san->buf.p[i] < 127 ? (char)san->buf.p[i] : '?';
        name[n] = 0;
        if(!seen) {
            memcpy(first, name, n + 1);
            seen = true;
        }
        if(event(p, "package_dns_san", 0, name)) return TB2_PROBE_IO_ERROR;
    }
    int rc =
        mbedtls_x509_crt_verify(leaf, ca, NULL, p->historical ? NULL : host, &flags, NULL, NULL);
    if(p->historical && rc &&
       !(flags & ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)))
        rc = 0;
    bool reissue = p->allow_reissue && rc && flags == MBEDTLS_X509_BADCERT_CN_MISMATCH;
    if(reissue) rc = 0;
    if(!rc) rc = mbedtls_x509_crt_check_key_usage(leaf, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if(!rc)
        rc = mbedtls_x509_crt_check_extended_key_usage(
            leaf, MBEDTLS_OID_SERVER_AUTH, MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH));
    char detail[208];
    snprintf(
        detail,
        sizeof(detail),
        "%s required_host=%s first_DNS_SAN=%s verify_flags=0x%08lx",
        tb2_package_names[index],
        p->historical ? "historical SAN retained" : host,
        first,
        (unsigned long)flags);
    if(rc) return error(p, rc, tb2_package_names[index], detail);
    if(reissue) p->result->reissue |= 1U << index;
    return event(p, "package_server_verified", 0, detail);
}
static int package_digest(Package* p) {
    mbedtls_sha256_context hash;
    mbedtls_sha256_init(&hash);
    int rc = mbedtls_sha256_starts(&hash, 0);
    for(unsigned i = 0; !rc && i < TB2_PACKAGE_FILES; i++) {
        size_t size = 0;
        rc = read_file(p, i, &size);
        uint8_t frame[5] = {
            (uint8_t)i,
            (uint8_t)size,
            (uint8_t)(size >> 8),
            (uint8_t)(size >> 16),
            (uint8_t)(size >> 24)};
        if(!rc) rc = mbedtls_sha256_update(&hash, frame, sizeof(frame));
        if(!rc) rc = mbedtls_sha256_update(&hash, p->bytes, size);
    }
    if(!rc) rc = mbedtls_sha256_finish(&hash, p->result->package_sha256);
    mbedtls_sha256_free(&hash);
    release_buffer(p);
    return rc;
}

static int package_run(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    uint32_t approved_missing,
    Tb2PackageResult* result,
    bool allow_reissue,
    bool historical) {
    memset(result, 0, sizeof(*result));
    if(!tb2_package_options_valid(options)) {
        snprintf(
            result->error,
            sizeof(result->error),
            "Invalid hostnames or UTC date; no files created.");
        return TB2_PROBE_CHECK_FAILED;
    }
    Package* p = calloc(1, sizeof(*p));
    if(!p) return TB2_PROBE_IO_ERROR;
    p->io = io;
    p->options = options;
    p->result = result;
    p->allow_reissue = allow_reissue;
    p->historical = historical;
    mbedtls_x509_crt ca;
    mbedtls_pk_context ca_key;
    mbedtls_x509_crt_init(&ca);
    mbedtls_pk_init(&ca_key);
    int rc = tb2_probe_crypto_begin();
    int cr = rc ? rc : parse_cert(p, 0, &ca), kr = rc ? rc : parse_key(p, 1, &ca_key);
    if(cr && cr != TB2_PACKAGE_MISSING) rc = cr;
    if(!rc && kr && kr != TB2_PACKAGE_MISSING) rc = kr;
    if(!rc && !cr && kr == TB2_PACKAGE_MISSING)
        rc = error(
            p,
            TB2_PROBE_CHECK_FAILED,
            tb2_package_names[1],
            "Missing for existing CA; a new key would not match");
    if(!rc && !cr) rc = root_check(p, &ca);
    if(!rc && !cr && !kr) rc = pair(p, 0, &ca, &ca_key);
    /* Inspect both leaf pairs even if the CA is absent; corrupted files must
     * not be masked by a generic missing-file confirmation. */
    for(unsigned index = 2; !rc && index < TB2_PACKAGE_FILES; index += 2) {
        mbedtls_x509_crt leaf;
        mbedtls_pk_context key;
        mbedtls_x509_crt_init(&leaf);
        mbedtls_pk_init(&key);
        int lr = parse_cert(p, index, &leaf), lk = parse_key(p, index + 1, &key);
        if(lr && lr != TB2_PACKAGE_MISSING) rc = lr;
        if(!rc && lk && lk != TB2_PACKAGE_MISSING) rc = lk;
        if(!rc && !lr && (lk == TB2_PACKAGE_MISSING || cr == TB2_PACKAGE_MISSING))
            rc = error(
                p,
                TB2_PROBE_CHECK_FAILED,
                tb2_package_names[index],
                "Certificate exists but key or root is missing; import the original file");
        if(!rc && !lr) rc = pair(p, index, &leaf, &key);
        if(!rc && !lr)
            rc = leaf_check(
                p, index, &leaf, &ca, index == 2 ? options->https_host : options->ici_host);
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&leaf);
    }
    if(!rc && !cr && (result->missing & ((1U << 2) | (1U << 4)))) {
        char limit[32];
        snprintf(
            limit,
            sizeof(limit),
            "%04d%02d%02d%02d%02d%02d",
            ca.valid_to.year,
            ca.valid_to.mon,
            ca.valid_to.day,
            ca.valid_to.hour,
            ca.valid_to.min,
            ca.valid_to.sec);
        if(strcmp(options->expires, limit) > 0) {
            char detail[120];
            snprintf(
                detail,
                sizeof(detail),
                "New server certificate outlives CA (%s). Adjust expires_utc explicitly.",
                limit);
            rc = error(p, TB2_PROBE_CHECK_FAILED, "Validity", detail);
        }
    }
    if(!rc && result->missing && (result->missing & approved_missing) != result->missing) {
        snprintf(
            result->error,
            sizeof(result->error),
            "Confirm missing files before generation (mask=0x%02lx).",
            (unsigned long)result->missing);
        rc = TB2_PACKAGE_MISSING;
    }
    if(!rc &&
       (result->reissue & (approved_missing >> TB2_PACKAGE_REISSUE_SHIFT)) != result->reissue) {
        snprintf(
            result->error,
            sizeof(result->error),
            "Confirm server certificate update; CA and keys retained.");
        rc = TB2_PACKAGE_MISSING;
    }
    if(!rc && kr == TB2_PACKAGE_MISSING) rc = generate_key(p, 1, &ca_key);
    if(!rc && cr == TB2_PACKAGE_MISSING) rc = issue(p, 0, NULL, &ca_key, &ca, &ca_key, NULL);
    if(!rc) rc = root_check(p, &ca);
    p->allow_reissue = false; /* Newly issued leaves must match, without exception. */
    for(unsigned index = 2; !rc && index < TB2_PACKAGE_FILES; index += 2) {
        mbedtls_x509_crt leaf;
        mbedtls_pk_context key;
        mbedtls_x509_crt_init(&leaf);
        mbedtls_pk_init(&key);
        rc = boundary(p, tb2_package_names[index]);
        if(!rc) rc = parse_key(p, index + 1, &key);
        if(rc == TB2_PACKAGE_MISSING) rc = generate_key(p, index + 1, &key);
        if(!rc) rc = parse_cert(p, index, &leaf);
        if(rc == TB2_PACKAGE_MISSING || (!rc && (result->reissue & (1U << index))))
            rc = issue(
                p,
                index,
                &ca,
                &ca_key,
                &leaf,
                &key,
                index == 2 ? options->https_host : options->ici_host);
        if(!rc) rc = pair(p, index, &leaf, &key);
        if(!rc)
            rc = leaf_check(
                p, index, &leaf, &ca, index == 2 ? options->https_host : options->ici_host);
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&leaf);
    }
    if(!rc) rc = package_digest(p);
    if(!rc && allow_reissue && approved_missing) {
        for(unsigned i = 0; !rc && i < TB2_PACKAGE_FILES; i++) {
            size_t size;
            rc = read_file(p, i, &size);
            if(!rc) rc = save(p, tb2_package_names[i], p->bytes, size);
        }
    }
    if(!rc && approved_missing) rc = save(p, "ca.der", ca.raw.p, ca.raw.len);
    if(!rc) {
        char hex[65];
        hex_digest(result->ca_sha256, hex);
        rc = event(p, "package_ca_sha256", 0, hex);
    }
    mbedtls_pk_free(&ca_key);
    mbedtls_x509_crt_free(&ca);
    if(p->io_failed) rc = TB2_PROBE_IO_ERROR;
    if(io->cancelled(io->context)) rc = TB2_PROBE_CANCELLED;
    if(tb2_probe_crypto_current()) rc = TB2_PROBE_CHECK_FAILED;
    if(rc && rc != TB2_PACKAGE_MISSING && !result->error[0])
        error(p, rc, "Certificate package", "Validation or generation incomplete");
    if(!io->event(
           io->context,
           "package_finished",
           rc,
           result->error[0] ? result->error : "keys, chain, hosts and UTC dates verified"))
        rc = TB2_PROBE_IO_ERROR;
    release_buffer(p);
    mbedtls_platform_zeroize(p, sizeof(*p));
    free(p);
    return rc;
}

int tb2_package_run(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    uint32_t approval,
    Tb2PackageResult* result) {
    return package_run(io, options, approval, result, false, false);
}
int tb2_package_update(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    uint32_t approval,
    Tb2PackageResult* result) {
    return package_run(io, options, approval, result, true, false);
}
int tb2_package_inspect(
    Tb2PackageIO* io,
    const Tb2PackageOptions* options,
    bool export_ca_der,
    Tb2PackageResult* result) {
    return package_run(
        io, options, export_ca_der ? TB2_PACKAGE_EXPORT_DER : 0, result, false, true);
}
