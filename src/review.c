#include "review.h"
#include <stdio.h>

void tb2_review_approval(const Tb2SetupRequest* r, char* text, size_t capacity) {
    char fingerprint[65] = {0};
    if(r->flow)
        for(unsigned i = 0; i < 32; i++)
            snprintf(fingerprint + i * 2, 3, "%02x", r->flow->package.ca_sha256[i]);
    int count = snprintf(
        text,
        capacity,
        "Check results\nBox: %s\nDump: %s\nTarget: %s\nLFS: 0x%08lx / %lu blocks\nConfirm UTC: %s\nExpires: %s\n%s\nCA SHA256: %s\nHTTPS certificate: %s\nICI certificate: %s\nMissing files:\n",
        r->box_alias,
        r->spec->source,
        r->spec->output_path,
        (unsigned long)(r->flow ? r->flow->read.offset : 0),
        (unsigned long)(r->flow ? r->flow->read.block_count : 0),
        r->spec->options.now,
        r->spec->options.expires,
        r->flow && (r->flow->package.missing & 1U) ? "New CA: update BOTH TeddyCloud and box!" :
                                                     "Keep existing CA",
        r->flow && (r->flow->package.missing & 1U) ? "(will be generated)" : fingerprint,
        r->spec->options.https_host,
        r->spec->options.ici_host);
    size_t used = count > 0 && (size_t)count < capacity ? (size_t)count : capacity - 1;
    for(unsigned i = 0; r->flow && i < TB2_PACKAGE_FILES; i++)
        if(r->flow->package.missing & (1U << i)) {
            count = snprintf(text + used, capacity - used, "%s\n", tb2_package_names[i]);
            if(count > 0 && (size_t)count < capacity - used) used += count;
        }
    snprintf(
        text + used,
        capacity - used,
        "\nSettings: %s\nHost: %s\nHTTPS port: %u%s\nMQTT port: %u%s\n%s\n%s\nOriginal retained. Back: approval.",
        r->spec->server.fields ? "Change" : "Keep",
        r->spec->server.fields & TB2_SERVER_HOST ? r->spec->server.host : "unchanged",
        tb2_server_port(&r->spec->server, false),
        r->spec->server.fields & TB2_SERVER_HTTPS ? "" : " (unchanged)",
        tb2_server_port(&r->spec->server, true),
        r->spec->server.fields & TB2_SERVER_MQTT ? "" : " (unchanged)",
        r->flow && r->flow->package.reissue ? "Reissue server certificates; retain CA and keys." :
                                              "No server reissue required.",
        r->operation && r->operation->kind == Tb2OperationAio ?
            "Will flash: W25Q128FV / same chip UID" :
            "Modify image only");
}
