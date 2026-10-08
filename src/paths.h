#pragma once

/* Shared SD location for dump/key/package selection and new image output.
 * Job metadata, original backups and generated private keys stay job-local. */
#define TB2_APP_ROOT     "/ext/apps_data/tb2_manager"
#define TB2_JOBS_ROOT    TB2_APP_ROOT "/jobs"
#define TB2_BOXES_ROOT   TB2_APP_ROOT "/boxes"
#define TB2_OBJECTS_ROOT TB2_APP_ROOT "/objects"
#define TB2_IMAGES_ROOT  TB2_APP_ROOT "/images"
#define TB2_SPI_MEM_ROOT TB2_APP_ROOT
#define TB2_IMAGE_PREFIX "tb2-"
#define TB2_LEGACY_IMAGE "image.bin"
#define TB2_CONFIG_PATH  TB2_APP_ROOT "/builder.conf"
