#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TB2_FILE_VERSION_DIGITS 5U
#define TB2_FILE_VERSION_TEXT   9U
/** User-confirmed filename label, independent of MCUboot identity and local ID. */
typedef struct {
    uint8_t major, minor, patch;
} Tb2FileVersion;
bool tb2_file_version_valid(const Tb2FileVersion*);
bool tb2_file_version_parse(const char*, Tb2FileVersion*);
bool tb2_file_version_format(const Tb2FileVersion*, char*, size_t);
int tb2_file_version_compare(const Tb2FileVersion*, const Tb2FileVersion*);
void tb2_file_version_digits(const Tb2FileVersion*, uint8_t digits[TB2_FILE_VERSION_DIGITS]);
void tb2_file_version_from_digits(Tb2FileVersion*, const uint8_t digits[TB2_FILE_VERSION_DIGITS]);
