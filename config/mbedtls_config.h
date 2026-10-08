#pragma once

/* Resource-probe configuration, not a network/TLS stack. Keep both TB2 curves. */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_AES_ROM_TABLES
/* FAP constants also occupy RAM. This removes the table-generation routine,
 * not the tables' runtime memory; it does not change AES or key storage. */
#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#ifndef TB2_CORE_MODULE
#define MBEDTLS_BASE64_C
#endif
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_WINDOW_SIZE       2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 0
/* Generic NIST reduction saves code RAM on an SD-loaded FAP. The library
 * documents slower ECC; UI stays on its own thread and shows the current step. */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA512_SMALLER
#define MBEDTLS_HKDF_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#ifndef TB2_CORE_MODULE
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C
#endif
#define MBEDTLS_X509_USE_C
#ifndef TB2_CORE_MODULE
#define MBEDTLS_X509_CREATE_C
#endif
#define MBEDTLS_X509_CRT_PARSE_C
#ifndef TB2_CORE_MODULE
#define MBEDTLS_X509_CRT_WRITE_C
#endif
#define MBEDTLS_ERROR_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
/* No wall-clock acceptance in these fixed-date synthetic fixtures. The eventual
 * builder must explicitly validate dates against the user-confirmed RTC. */
