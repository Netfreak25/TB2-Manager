#include "file_version.h"
#include <stdio.h>

bool tb2_file_version_valid(const Tb2FileVersion* v) {
    return v && v->major <= 9 && v->minor <= 99 && v->patch <= 99;
}
bool tb2_file_version_parse(const char* text, Tb2FileVersion* result) {
    if(!text || !result) return false;
    unsigned parts[3] = {0};
    for(unsigned i = 0; i < 3; i++) {
        unsigned count = 0;
        while(*text >= '0' && *text <= '9') {
            if(++count > (i ? 2U : 1U)) return false;
            parts[i] = parts[i] * 10U + (unsigned)(*text++ - '0');
        }
        if(!count || (i < 2 && *text++ != '.')) return false;
    }
    /* MCUboot's build suffix stays separate from the editable label. */
    if(*text == '+') {
        text++;
        if(*text < '0' || *text > '9') return false;
        while(*text >= '0' && *text <= '9')
            text++;
    }
    if(*text) return false;
    *result = (Tb2FileVersion){(uint8_t)parts[0], (uint8_t)parts[1], (uint8_t)parts[2]};
    return true;
}
bool tb2_file_version_format(const Tb2FileVersion* v, char* out, size_t capacity) {
    if(!out || !capacity || !tb2_file_version_valid(v)) return false;
    int n = snprintf(out, capacity, "%u.%u.%u", v->major, v->minor, v->patch);
    return n > 0 && (size_t)n < capacity;
}
int tb2_file_version_compare(const Tb2FileVersion* a, const Tb2FileVersion* b) {
    if(a->major != b->major) return a->major < b->major ? -1 : 1;
    if(a->minor != b->minor) return a->minor < b->minor ? -1 : 1;
    return a->patch == b->patch ? 0 : a->patch < b->patch ? -1 : 1;
}
void tb2_file_version_digits(const Tb2FileVersion* v, uint8_t digits[TB2_FILE_VERSION_DIGITS]) {
    digits[0] = v->major;
    digits[1] = v->minor / 10;
    digits[2] = v->minor % 10;
    digits[3] = v->patch / 10;
    digits[4] = v->patch % 10;
}
void tb2_file_version_from_digits(Tb2FileVersion* v, const uint8_t digits[TB2_FILE_VERSION_DIGITS]) {
    *v = (Tb2FileVersion){
        digits[0], (uint8_t)(digits[1] * 10 + digits[2]), (uint8_t)(digits[3] * 10 + digits[4])};
}
