#include "job.h"
#include <stdio.h>
#include <string.h>

#define JOB_MAGIC 0x324a4254U

bool tb2_job_spec_size(size_t size) {
    return size == TB2_JOB_LEGACY_SPEC_SIZE || size == TB2_JOB_SHARED_SPEC_SIZE ||
           size == TB2_JOB_OUTPUT_SPEC_SIZE || size == TB2_JOB_SPEC_SIZE;
}

static bool spec_valid(const Tb2JobSpec* spec) {
    return memchr(spec->source, 0, sizeof(spec->source)) &&
           memchr(spec->imported_package, 0, sizeof(spec->imported_package)) &&
           memchr(spec->output_path, 0, sizeof(spec->output_path)) && spec->shared_image <= 2 &&
           spec->export_archive <= 1 && tb2_server_change_valid(&spec->server) &&
           tb2_package_options_valid(&spec->options);
}

bool tb2_job_spec_equal(const Tb2JobSpec* a, const Tb2JobSpec* b) {
    /* Ignore uninitialized string tails; every persisted choice remains bound. */
    return spec_valid(a) && spec_valid(b) && !strcmp(a->source, b->source) &&
           !strcmp(a->imported_package, b->imported_package) &&
           !strcmp(a->options.https_host, b->options.https_host) &&
           !strcmp(a->options.ici_host, b->options.ici_host) &&
           !strcmp(a->options.now, b->options.now) &&
           !strcmp(a->options.expires, b->options.expires) && a->shared_image == b->shared_image &&
           !strcmp(a->output_path, b->output_path) && a->export_archive == b->export_archive &&
           a->server.fields == b->server.fields && !strcmp(a->server.host, b->server.host) &&
           !memcmp(a->server.ports, b->server.ports, 4);
}

bool tb2_job_spec_encode(const Tb2JobSpec* spec, uint8_t bytes[TB2_JOB_SPEC_SIZE]) {
    if(!spec || !spec_valid(spec)) return false;
    memset(bytes, 0, TB2_JOB_SPEC_SIZE);
    memcpy(bytes, spec->source, strlen(spec->source));
    memcpy(bytes + 256, spec->imported_package, strlen(spec->imported_package));
    memcpy(bytes + 512, spec->options.https_host, strlen(spec->options.https_host));
    memcpy(bytes + 576, spec->options.ici_host, strlen(spec->options.ici_host));
    memcpy(bytes + 640, spec->options.now, TB2_DATE_SIZE);
    memcpy(bytes + 655, spec->options.expires, TB2_DATE_SIZE);
    bytes[670] = spec->shared_image;
    memcpy(bytes + 671, spec->output_path, strlen(spec->output_path));
    bytes[927] = 2; /* Extension version. Bytes 929-930 reserved and zero. */
    bytes[928] = spec->export_archive;
    memcpy(bytes + 931, spec->server.host, strlen(spec->server.host));
    memcpy(bytes + 995, spec->server.ports, 4);
    bytes[999] = spec->server.fields;
    return true;
}

bool tb2_job_spec_decode(const uint8_t* bytes, size_t size, Tb2JobSpec* spec) {
    memset(spec, 0, sizeof(*spec));
    if(!tb2_job_spec_size(size)) return false;
    memcpy(spec->source, bytes, 256);
    memcpy(spec->imported_package, bytes + 256, 256);
    memcpy(spec->options.https_host, bytes + 512, 64);
    memcpy(spec->options.ici_host, bytes + 576, 64);
    memcpy(spec->options.now, bytes + 640, TB2_DATE_SIZE);
    memcpy(spec->options.expires, bytes + 655, TB2_DATE_SIZE);
    if(size >= TB2_JOB_SHARED_SPEC_SIZE) spec->shared_image = bytes[670];
    if(size >= TB2_JOB_OUTPUT_SPEC_SIZE) memcpy(spec->output_path, bytes + 671, 256);
    if(size == TB2_JOB_SPEC_SIZE) {
        if(bytes[927] != 2 || bytes[929] || bytes[930]) return false;
        spec->export_archive = bytes[928];
        memcpy(spec->server.host, bytes + 931, 64);
        memcpy(spec->server.ports, bytes + 995, 4);
        spec->server.fields = bytes[999];
    }
    return spec_valid(spec);
}

bool tb2_job_image_path(
    const Tb2JobSpec* spec,
    const char* directory,
    char output[TB2_JOB_PATH_MAX]) {
    const char* id = strrchr(directory, '/');
    id = id ? id + 1 : directory;
    if(spec->shared_image > 2 || !tb2_job_relative_path(id)) return false;
    if(spec->shared_image == 2 &&
       (strncmp(spec->output_path, "/ext/", 5) || strstr(spec->output_path, "/../") ||
        strstr(spec->output_path, "/./") || strstr(spec->output_path, "//") ||
        strlen(spec->output_path) < 10 ||
        strcmp(spec->output_path + strlen(spec->output_path) - 4, ".bin")))
        return false;
    if(spec->shared_image == 2)
        for(const char* p = spec->output_path; *p; p++)
            if((unsigned char)*p < 32 || strchr("\\:*?\"<>|", *p)) return false;
    int n = spec->shared_image == 2 ?
                snprintf(output, TB2_JOB_PATH_MAX, "%s", spec->output_path) :
            spec->shared_image ?
                snprintf(
                    output, TB2_JOB_PATH_MAX, TB2_SPI_MEM_ROOT "/" TB2_IMAGE_PREFIX "%s.bin", id) :
                snprintf(output, TB2_JOB_PATH_MAX, "%s/" TB2_LEGACY_IMAGE, directory);
    if(n <= 0 || n >= (int)TB2_JOB_PATH_MAX) return false;
    /* FAT filenames are case-insensitive. Never reopen the source for writes. */
    size_t i = 0;
    for(; output[i] && spec->source[i]; i++) {
        unsigned a = (unsigned char)output[i], b = (unsigned char)spec->source[i];
        if(a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if(b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if(a != b) return true;
    }
    return output[i] != spec->source[i];
}

static void put32(uint8_t* out, uint32_t value) {
    for(unsigned i = 0; i < 4; i++)
        out[i] = (uint8_t)(value >> (8 * i));
}
static uint32_t get32(const uint8_t* in) {
    uint32_t value = 0;
    for(unsigned i = 0; i < 4; i++)
        value |= (uint32_t)in[i] << (8 * i);
    return value;
}
uint32_t tb2_job_crc(const void* bytes, size_t size) {
    const uint8_t* data = bytes;
    uint32_t crc = UINT32_MAX;
    for(size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for(unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1)));
    }
    return ~crc;
}
bool tb2_job_relative_path(const char* name) {
    size_t size = 0, segment = 0;
    for(; size < TB2_JOB_NAME_MAX && name[size]; size++) {
        unsigned char c = (unsigned char)name[size];
        if(c < 32 || c == '\\' || c == ':' || c >= 127) return false;
        if(c == '/') {
            if(!segment || (segment == 1 && name[size - 1] == '.') ||
               (segment == 2 && name[size - 1] == '.' && name[size - 2] == '.'))
                return false;
            segment = 0;
        } else
            segment++;
    }
    return size > 0 && size < TB2_JOB_NAME_MAX && segment > 0 &&
           !(segment == 1 && name[size - 1] == '.') &&
           !(segment == 2 && name[size - 1] == '.' && name[size - 2] == '.');
}
void tb2_job_encode(const Tb2JobRecord* r, uint8_t out[TB2_JOB_RECORD_SIZE]) {
    memset(out, 0, TB2_JOB_RECORD_SIZE);
    put32(out, JOB_MAGIC);
    put32(out + 4, TB2_JOB_VERSION);
    put32(out + 8, r->sequence);
    put32(out + 12, (uint32_t)r->kind);
    put32(out + 16, r->size);
    put32(out + 20, r->flags);
    memcpy(out + 24, r->name, TB2_JOB_NAME_MAX);
    memcpy(out + 184, r->digest, 32);
    memcpy(out + 216, r->payload, 64);
    put32(out + 280, tb2_job_crc(out, 280));
}
bool tb2_job_decode(const uint8_t in[TB2_JOB_RECORD_SIZE], uint32_t sequence, Tb2JobRecord* r) {
    memset(r, 0, sizeof(*r));
    if(get32(in) != JOB_MAGIC || get32(in + 4) != TB2_JOB_VERSION || get32(in + 8) != sequence ||
       get32(in + 280) != tb2_job_crc(in, 280) || get32(in + 12) < Tb2JobFilePending ||
       get32(in + 12) > Tb2JobImageStarted || !memchr(in + 24, 0, TB2_JOB_NAME_MAX))
        return false;
    r->sequence = sequence;
    r->kind = (Tb2JobRecordKind)get32(in + 12);
    r->size = get32(in + 16);
    r->flags = get32(in + 20);
    memcpy(r->name, in + 24, TB2_JOB_NAME_MAX);
    memcpy(r->digest, in + 184, 32);
    memcpy(r->payload, in + 216, 64);
    if(r->kind == Tb2JobFilePending || r->kind == Tb2JobFileDone || r->kind == Tb2JobFileDiscarded)
        return tb2_job_relative_path(r->name);
    return true;
}
void tb2_job_set_read(Tb2JobRecord* r, const Tb2ReadResult* result) {
    r->kind = Tb2JobReadDone;
    memcpy(r->digest, result->source_sha256, 32);
    put32(r->payload, result->offset);
    put32(r->payload + 4, result->block_count);
    put32(r->payload + 8, result->disk_version);
    put32(r->payload + 12, result->encrypted_files);
    put32(r->payload + 16, result->profile);
}
bool tb2_job_get_read(const Tb2JobRecord* r, Tb2ReadResult* result) {
    memset(result, 0, sizeof(*result));
    if(r->kind != Tb2JobReadDone) return false;
    result->offset = get32(r->payload);
    result->block_count = get32(r->payload + 4);
    result->disk_version = get32(r->payload + 8);
    result->encrypted_files = get32(r->payload + 12);
    result->profile = get32(r->payload + 16);
    memcpy(result->source_sha256, r->digest, 32);
    return result->offset < TB2_IMAGE_SIZE && result->offset % TB2_LFS_BLOCK_SIZE == 0 &&
           result->block_count >= 2 &&
           result->block_count <= (TB2_IMAGE_SIZE - result->offset) / TB2_LFS_BLOCK_SIZE &&
           result->disk_version >= 0x00020000U && result->disk_version <= 0x00020001U &&
           result->profile >= 1 && result->profile <= 3;
}
bool tb2_job_parse_config(const char* text, size_t size, Tb2JobSpec* spec, char error[224]) {
    unsigned seen = 0;
    size_t start = 0;
    while(start < size) {
        size_t end = start;
        while(end < size && text[end] != '\n')
            end++;
        size_t length = end - start;
        if(length && text[start + length - 1] == '\r') length--;
        const char* line = text + start;
        start = end + (end < size);
        if(!length || line[0] == '#') continue;
        const char* equal = memchr(line, '=', length);
        if(!equal || memchr(line, 0, length)) goto invalid;
        size_t key = (size_t)(equal - line), value = length - key - 1;
        const char* names[] = {"https_host", "ici_host", "expires_utc", "package_dir"};
        char* outputs[] = {
            spec->options.https_host,
            spec->options.ici_host,
            spec->options.expires,
            spec->imported_package};
        const size_t limits[] = {TB2_HOST_MAX, TB2_HOST_MAX, TB2_DATE_SIZE, TB2_JOB_PATH_MAX};
        unsigned field = 0;
        for(; field < 4; field++)
            if(strlen(names[field]) == key && !memcmp(line, names[field], key)) break;
        if(field == 4 || (seen & (1U << field)) || value >= limits[field]) goto invalid;
        seen |= 1U << field;
        memcpy(outputs[field], equal + 1, value);
        outputs[field][value] = 0;
    }
    if(!tb2_package_options_valid(&spec->options)) goto invalid;
    if(spec->imported_package[0] && strncmp(spec->imported_package, "/ext/", 5)) goto invalid;
    return true;
invalid:
    snprintf(
        error,
        224,
        "builder.conf: invalid, duplicate or unknown field. Check https_host, ici_host, expires_utc, package_dir.");
    return false;
}
