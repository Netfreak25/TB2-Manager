#pragma once
/* FBT defines a firmware-wide Mbed TLS subset. This private library must NOT
 * accidentally inherit its ABI/configuration; every translation unit uses ours. */
#undef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "tb2_mbedtls_config.h"
