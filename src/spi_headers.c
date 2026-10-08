#include "spi.h"
#include "probe.h"
#include <stdio.h>
#include <string.h>

#define HEADER_BYTES    32U
#define HEADER_POLL_MS  50U
#define HEADER_READY_MS 1000U

static uint32_t header_u32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bool stopped(Tb2SpiRequest* r) {
    return r->io->cancelled && r->io->cancelled(r->io->context);
}
static int header_error(Tb2SpiRequest* r, int rc, const char* text) {
    snprintf(r->headers->error, sizeof(r->headers->error), "%s", text);
    return rc;
}
static void parse_header(const uint8_t bytes[HEADER_BYTES], Tb2SlotHeader* slot) {
    bool empty = true;
    for(size_t i = 0; i < HEADER_BYTES; i++)
        empty &= bytes[i] == 0xff;
    slot->status = empty ? Tb2HeaderEmpty : Tb2HeaderUnknown;
    if(empty || header_u32(bytes) != TB2_MCUBOOT_MAGIC) return;
    uint32_t header_size = bytes[8] | (uint32_t)bytes[9] << 8;
    uint32_t payload = header_u32(bytes + 12);
    uint32_t protected_size = bytes[10] | (uint32_t)bytes[11] << 8;
    slot->status = Tb2HeaderInvalid;
    if(header_size < HEADER_BYTES || header_size > TB2_SLOT_SIZE || !payload ||
       payload > TB2_SLOT_SIZE - header_size ||
       protected_size > TB2_SLOT_SIZE - header_size - payload)
        return;
    slot->status = Tb2HeaderValid;
    slot->major = bytes[20];
    slot->minor = bytes[21];
    slot->revision = bytes[22] | (uint16_t)bytes[23] << 8;
    slot->build = header_u32(bytes + 24);
}

static void header_report(Tb2SlotHeaders* result) {
    static const char* const names[] = {
        "Not read", "", "Empty", "Unknown header", "Invalid header", "Read failed"};
    char labels[2][32], builds[2][16];
    for(unsigned i = 0; i < 2; i++) {
        const Tb2SlotHeader* slot = &result->slots[i];
        if(slot->status == Tb2HeaderValid) {
            snprintf(
                labels[i], sizeof(labels[i]), "%u.%u.%u", slot->major, slot->minor, slot->revision);
            snprintf(builds[i], sizeof(builds[i]), "%lu", (unsigned long)slot->build);
        } else {
            snprintf(labels[i], sizeof(labels[i]), "%s", names[slot->status]);
            strcpy(builds[i], "Unknown");
        }
    }
    snprintf(
        result->summary,
        sizeof(result->summary),
        "Slot A: %s\nSlot B: %s\nHeader values only",
        labels[0],
        labels[1]);
    snprintf(
        result->details,
        sizeof(result->details),
        "Slot A: %s\nBuild: %s\nSlot B: %s\nBuild: %s\n\nHeader values only.\nActive slot unknown.\nNo firmware verification.",
        labels[0],
        builds[0],
        labels[1],
        builds[1]);
}

/** Separate read-only path: no UID, file callbacks, hashing, checkpoints or leases. */
int tb2_spi_headers_run(Tb2SpiTransport* bus, Tb2SpiRequest* r) {
    if(!r || !r->headers) return TB2_PROBE_CHECK_FAILED;
    memset(r->headers, 0, sizeof(*r->headers));
    if(!bus || !bus->begin || !bus->end || !bus->transfer || !bus->milliseconds || !bus->delay ||
       !r->io)
        return header_error(r, TB2_PROBE_CHECK_FAILED, "Invalid header request.");
    if(!bus->begin(bus->context))
        return header_error(r, Tb2SpiTransportError, "SPI unavailable. Retry.");
    int rc = 0;
    if(r->waiting) r->waiting(r->wait_context, true);
    if(r->io->progress) r->io->progress(r->io->context, "Waiting for chip", 0, 0);
    for(;;) {
        if(stopped(r)) {
            rc = TB2_PROBE_CANCELLED;
            break;
        }
        uint8_t cmd = 0x9f, id[3] = {0};
        if(bus->transfer(bus->context, &cmd, 1, id, sizeof(id)) && id[0] && id[0] != 0xff) {
            if(id[0] != 0xef || id[1] != 0x40 || id[2] != 0x18)
                rc = header_error(r, Tb2SpiUnsupported, "Unsupported chip. Expected W25Q128FV.");
            break;
        }
        bus->delay(bus->context, HEADER_POLL_MS);
    }
    uint32_t start = bus->milliseconds(bus->context);
    while(!rc) {
        if(stopped(r)) {
            rc = TB2_PROBE_CANCELLED;
            break;
        }
        uint8_t cmd = 0x05, status = 0;
        if(!bus->transfer(bus->context, &cmd, 1, &status, 1)) {
            rc = header_error(r, Tb2SpiTransportError, "Cannot read chip status. Retry.");
            break;
        }
        if(!(status & 1U)) break;
        if(bus->milliseconds(bus->context) - start >= HEADER_READY_MS) {
            rc = header_error(r, Tb2SpiTimeout, "Chip busy. Wait and retry.");
            break;
        }
        bus->delay(bus->context, HEADER_POLL_MS);
    }
    if(r->waiting) r->waiting(r->wait_context, false);
    if(!rc) {
        const uint32_t offsets[] = {TB2_PRIMARY_OFFSET, TB2_SECONDARY_OFFSET};
        for(unsigned i = 0; i < 2; i++) {
            if(stopped(r)) {
                rc = TB2_PROBE_CANCELLED;
                break;
            }
            if(r->io->progress)
                r->io->progress(
                    r->io->context, i ? "Read slot B header" : "Read slot A header", 0, 0);
            uint32_t offset = offsets[i];
            uint8_t cmd[] = {
                0x03, (uint8_t)(offset >> 16), (uint8_t)(offset >> 8), (uint8_t)offset};
            uint8_t bytes[HEADER_BYTES];
            if(bus->transfer(bus->context, cmd, sizeof(cmd), bytes, sizeof(bytes)))
                parse_header(bytes, &r->headers->slots[i]);
            else {
                r->headers->slots[i].status = Tb2HeaderReadFailed;
                rc = header_error(
                    r, Tb2SpiTransportError, "Header read failed. Check connection and retry.");
            }
        }
    }
    if(stopped(r)) rc = TB2_PROBE_CANCELLED;
    if(rc == TB2_PROBE_CANCELLED) header_error(r, rc, "Identification cancelled.");
    header_report(r->headers);
    bus->end(bus->context);
    return rc;
}
