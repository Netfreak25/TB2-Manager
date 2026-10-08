/* Relocatable FAP: keep .text at zero so the pinned loader's entry offset
 * remains valid. Mbed TLS arithmetic is independently allocated/relocated;
 * no single ~75 KiB executable heap block is required after UI allocation. */
.tb2math 0 : ALIGN(4) {
    *(.text.mbedtls_mpi_*)
    *(.text.mbedtls_ecp_*)
    *(.text.mbedtls_ecdsa_*)
    *(.text.mpi_*)
    *(.text.ecp_*)
    *(.text.ecdsa_*)
}
.tb2fs 0 : ALIGN(4) {
    *(.text.lfs_*)
}

/* Record storage consists of many independent, relocatable functions. Keep
 * them in a second executable allocation so the loader never needs one large
 * contiguous block for the Store module. The total resident payload is
 * unchanged and remains subject to the normal memory ceiling. */
.tb2records 0 : ALIGN(4) {
    *(.text.tb2_record_*)
    *(.text.tb2_box_*)
    *(.text.tb2_version_*)
    *(.text.tb2_secret_*)
    *(.text.tb2_entry_*)
    *(.text.tb2_object_*)
    *(.text.tb2_folder_*)
    *(.text.tb2_edition_*)
    *(.text.tb2_file_*)
    *(.text.tb2_server_package_*)
    *(.text.tb2_package_effective)
    *(.text.tb2_package_assign)
}
