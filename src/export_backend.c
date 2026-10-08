#include "setup.h"
#include "review.h"
#include <flipper_application/flipper_application.h>
#include <stdio.h>

static bool checkpoint(void* context, const Tb2ArchiveReceipt* receipt) {
    Tb2SetupRequest* r = context;
    r->operation->archive = *receipt;
    return tb2_operation_save(r->filesystem, r->directory, r->operation, false);
}
static bool run(Tb2SetupRequest* r) {
    if(r->kind == Tb2SetupRecordResult || r->kind == Tb2SetupOperationDetails ||
       r->kind == Tb2SetupApprove || r->kind == Tb2SetupResult || r->kind == Tb2SetupJobDetails ||
       r->kind == Tb2SetupOperationLog)
        return tb2_review_run(r);
    if(r->kind != Tb2SetupExport || !r->filesystem || !r->operation ||
       r->operation->state != Tb2UiRunning || r->operation->phase != Tb2PhaseExport ||
       !r->operation->modify_bound)
        return false;
    r->result = tb2_archive_image_lease(
        r->filesystem, r->operation->image, r->operation->image_hash, r->filesystem->image_lease);
    if(r->result) {
        snprintf(
            r->error,
            sizeof(r->error),
            "Saved image missing, changed or unreadable. Export stopped.");
        return true;
    }
    char package[TB2_JOB_PATH_MAX];
    snprintf(package, sizeof(package), "%s/package", r->directory);
    Tb2ArchiveRequest request = {
        .io = r->filesystem,
        .package_dir = package,
        .image_path = r->operation->image,
        .package_hash = r->operation->package_hash,
        .ca_hash = r->operation->ca_hash,
        .receipt = &r->operation->archive,
        .context = r,
        .checkpoint = checkpoint};
    r->result = tb2_archive_run(&request);
    snprintf(r->error, sizeof(r->error), "%s", request.error);
    return true;
}
static const Tb2Setup exporter = {.run = run};
static const FlipperAppPluginDescriptor descriptor = {
    .appid = TB2_EXPORT_ID,
    .ep_api_version = TB2_SETUP_API,
    .entry_point = &exporter};
const FlipperAppPluginDescriptor* tb2_export_entry(void) {
    return &descriptor;
}
