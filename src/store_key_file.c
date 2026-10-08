#include "store.h"
#include <storage/storage.h>
#include <stdio.h>
#include <string.h>

static bool key_event(Tb2StoreRequest* r, const char* operation, int code, const char* detail) {
    return !r->io->event || r->io->event(r->io->context, operation, code, detail);
}
/** Store only needs the bounded text decoder; image/KDF processing stays in Core. */
static bool store_parse_key(const char* text, size_t size, Tb2InputKey* input) {
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
        char c = text[i];
        unsigned value = c >= '0' && c <= '9' ? (unsigned)(c - '0') :
                         c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10) :
                         c >= 'A' && c <= 'F' ? (unsigned)(c - 'A' + 10) :
                                                16U;
        if(value > 15U) {
            memset(input, 0, sizeof(*input));
            return false;
        }
        input->bytes[i / 2] = (uint8_t)((input->bytes[i / 2] << 4) | value);
    }
    input->kind = size == TB2_SN_SIZE * 2 ? Tb2InputKeySecret : Tb2InputKeyAes;
    return true;
}
Tb2RecordResult tb2_store_task_key_file(Tb2StoreRequest* r) {
    Tb2RecordTask* task = r->task;
    if(!task ||
       (task->kind != Tb2RecordTaskKeyCandidate && task->kind != Tb2RecordTaskImportKey) ||
       !task->path[0])
        return Tb2RecordOk;
    r->source = task->path;
    r->key = &task->key;
    Tb2RecordResult rc = tb2_store_key_file(r);
    if(!rc && task->kind == Tb2RecordTaskImportKey) {
        task->import.stage = Tb2ImportKeyPreview;
        snprintf(
            task->report,
            sizeof(task->report),
            "Unverified key proposal\nType: %s\nVerified key kept until image validation.",
            task->key.kind == Tb2InputKeySecret ? "8-byte box secret" : "16-byte AES key");
    }
    if(rc) {
        task->result = rc;
        snprintf(task->report, sizeof(task->report), "%s", r->error);
    }
    return rc;
}
Tb2RecordResult tb2_store_key_file(Tb2StoreRequest* r) {
    if(!r->key || !r->source) return Tb2RecordCorrupt;
    memset(r->key, 0, sizeof(*r->key));
    Tb2RecordResult rc = Tb2RecordIo;
    char text[TB2_KEY_TEXT_MAX] = {0};
    File* file = storage_file_alloc(r->storage);
    bool opened = storage_file_open(file, r->source, FSAM_READ, FSOM_OPEN_EXISTING);
    bool ok =
        key_event(r, "key_file_open", storage_file_get_error(file), "path/content withheld") &&
        opened;
    if(ok) {
        uint64_t size = storage_file_size(file);
        if(!size || size > sizeof(text)) {
            rc = Tb2RecordCorrupt;
            memcpy(
                r->error,
                "Key file: 16 hex (secret) or 32 hex (AES); no JSON.",
                sizeof("Key file: 16 hex (secret) or 32 hex (AES); no JSON."));
            key_event(r, "key_file_size", rc, "empty or exceeds text limit");
            ok = false;
        } else {
            size_t actual = storage_file_read(file, text, (size_t)size);
            ok = key_event(
                     r,
                     "key_file_read",
                     actual == size ? 0 : (int)Tb2RecordIo,
                     "content withheld") &&
                 actual == size;
            if(ok && !store_parse_key(text, (size_t)size, r->key)) {
                rc = Tb2RecordCorrupt;
                memcpy(
                    r->error,
                    "Invalid key text: 16 or 32 hex digits; no JSON.",
                    sizeof("Invalid key text: 16 or 32 hex digits; no JSON."));
                key_event(r, "key_file_parse", rc, "invalid key text; value withheld");
                ok = false;
            }
        }
    }
    if(opened) {
        bool closed = storage_file_close(file);
        bool logged = key_event(
            r, "key_file_close", storage_file_get_error(file), closed ? "closed" : "close failed");
        if(!closed || !logged) rc = Tb2RecordIo;
        ok = closed && logged && ok;
    }
    storage_file_free(file);
    tb2_record_wipe(text, sizeof(text));
    if(ok) ok = key_event(r, "key_file_loaded", 0, "Key read; concrete dump validation pending");
    if(!ok) {
        tb2_record_wipe(r->key, sizeof(*r->key));
        if(!r->error[0])
            memcpy(
                r->error,
                "Key file or SD log error. Not decrypted.",
                sizeof("Key file or SD log error. Not decrypted."));
    }
    return ok ? Tb2RecordOk : rc;
}
