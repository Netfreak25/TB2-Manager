#include "operation.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

bool tb2_operation_bind(
    Tb2WorkflowIO* io,
    const char* directory,
    Tb2Operation* op,
    const Tb2JobSpec* spec) {
    uint8_t* bytes = malloc(TB2_JOB_SPEC_SIZE);
    char image[TB2_JOB_PATH_MAX], metadata[TB2_JOB_PATH_MAX];
    bool ok = bytes && tb2_job_spec_encode(spec, bytes) &&
              tb2_job_image_path(spec, directory, image);
    bool published_dump = ok && op->kind && op->phase == Tb2PhaseModifySetup &&
                          (op->dump.flags & Tb2SpiDumpVerified) && op->image[0] &&
                          !strcmp(op->image, spec->source);
    if(ok && op->kind && op->source[0]) ok = !strcmp(op->source, spec->source) || published_dump;
    int length = snprintf(metadata, sizeof(metadata), "%s/job.tb2", directory);
    int exists = ok && length > 0 && length < (int)sizeof(metadata) ?
                     io->exists(io->context, metadata) :
                     -1;
    if(exists == 1) {
        Tb2JobSpec* saved = malloc(sizeof(*saved));
        ok = saved && tb2_workflow_load(io, directory, saved) && tb2_job_spec_equal(saved, spec);
        free(saved);
    } else
        ok = exists == 0 && tb2_workflow_create(io, directory, spec);
    if(ok && op->kind) {
        uint32_t crc = tb2_job_crc(bytes, TB2_JOB_SPEC_SIZE);
        ok = !op->modify_bound || (op->spec_crc == crc && !strcmp(op->image, image));
        if(ok) {
            op->spec_crc = crc;
            op->modify_bound = true;
            if(!op->created[0]) memcpy(op->created, spec->options.now, TB2_DATE_SIZE);
            if(!published_dump) snprintf(op->source, sizeof(op->source), "%s", spec->source);
            snprintf(op->image, sizeof(op->image), "%s", image);
            op->phase = Tb2PhaseModifyCheck;
        }
    }
    free(bytes);
    return ok;
}
