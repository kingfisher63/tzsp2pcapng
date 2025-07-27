/*
 * Copyright (C) 2025 Roger Hunen
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation under the terms of the GNU General Public License is hereby 
 * granted. No representations are made about the suitability of this software 
 * for any purpose. It is provided "as is" without express or implied warranty.
 * See the GNU General Public License for more details.
 */

#include "tzsp2pcapng.h"

#include <string.h>

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

static inline size_t roundup( size_t x, size_t n ) {
    size_t r = x % n;
    return r == 0 ? x : x + n - r;
}

int
pcapng_maybe_flush( outfile_t *outfile )
{
    if (outfile->flush_every_packet) {
        if (fflush(outfile->fp) == EOF) {
            perror("ERROR: pcapng_maybe_flush");
            return -1;
        }
    }

    return 0;
}

uint64_t
pcapng_timestamp( struct timeval *timestamp, int ts_resolution )
{
    switch (ts_resolution) {
        case PCAPNG_TS_RESOLUTION_NSEC :
            return (uint64_t)timestamp->tv_sec * 1000000000 + (uint64_t)timestamp->tv_usec * 1000;

        case PCAPNG_TS_RESOLUTION_USEC :
            return (uint64_t)timestamp->tv_sec * 1000000 +    (uint64_t)timestamp->tv_usec;

        default :
            fprintf(stderr, "ERROR: invalid timestamp resolution (%d)\n", ts_resolution);
            return 0;
    }
}

int
pcapng_write_enhanced_packet_block( outfile_t *outfile, const uint8_t* data, size_t datalen, uint64_t timestamp )
{
    size_t caplen = MIN(datalen, PCAPNG_DEFAULT_SNAPLEN);

    pcapng_header_epb_t header = {
        .block_type         = PCAPNG_BLOCK_TYPE_EPB,
        .block_total_length = sizeof(pcapng_header_epb_t),
        .interface_id       = 0,
        .timestamp_upper    = (uint32_t)(timestamp >> 32),
        .timestamp_lower    = (uint32_t)(timestamp >>  0),
        .cap_len            = (uint32_t)caplen,
        .org_len            = (uint32_t)datalen
    };

    header.block_total_length += (uint32_t)roundup(caplen, 4);
    header.block_total_length += sizeof(header.block_total_length);

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_enhanced_packet_block: write header failed\n");
        return -1;
    }

    if (fwrite(data, 1, caplen, outfile->fp) != caplen) {
        fprintf(stderr, "ERROR: pcapng_write_enhanced_packet_block: write packet data failed\n");
        return -1;
    }

    if (pcapng_write_padding(outfile, caplen) == -1) {
        return -1;
    }

    if (fwrite(&header.block_total_length, sizeof(header.block_total_length), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_enhanced_packet_block: write block length failed\n");
        return -1;
    }

    outfile->size += header.block_total_length;

    return pcapng_maybe_flush(outfile);
}

int
pcapng_write_interface_description_block( outfile_t *outfile, const char* name, const char* description, uint16_t link_type, uint8_t ts_resolution )
{
    pcapng_header_idb_t header = {
        .block_type         = PCAPNG_BLOCK_TYPE_IDB,
        .block_total_length = sizeof(pcapng_header_idb_t),
        .link_type          = link_type,
        .reserved1          = 0,
        .snaplen            = PCAPNG_DEFAULT_SNAPLEN
    };

    header.block_total_length += (uint32_t)(name        != NULL ? sizeof(pcapng_header_opt_t) + roundup(strlen(name),        4) : 0);
    header.block_total_length += (uint32_t)(description != NULL ? sizeof(pcapng_header_opt_t) + roundup(strlen(description), 4) : 0);
    header.block_total_length += PCAPNG_OPTION_UINT8_TOTAL_LENGTH; // Timestamp resolution
    header.block_total_length += PCAPNG_OPTION_END_TOTAL_LENGTH;
    header.block_total_length += sizeof(header.block_total_length);

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_interface_description_block: write header failed\n");
        return -1;
    }

    if (name != NULL) {
        if (pcapng_write_option_string( outfile, PCAPNG_IDB_OPTION_NAME, name) == -1) {
            return -1;
        }
    }

    if (description != NULL) {
        if (pcapng_write_option_string(outfile, PCAPNG_IDB_OPTION_DESCRIPTION, description) == -1) {
            return -1;
        }
    }

    if (pcapng_write_option_uint8(outfile, PCAPNG_IDB_OPTION_TS_RESOLUTION, ts_resolution) == -1) {
        return -1;
    }

    if (pcapng_write_option_end(outfile) == -1) {
        return -1;
    }

    if (fwrite(&header.block_total_length, sizeof(header.block_total_length), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_interface_description_block: write block length failed\n");
        return -1;
    }

    outfile->size += header.block_total_length;

    return pcapng_maybe_flush(outfile);
}

int
pcapng_write_option_end( outfile_t *outfile )
{
    pcapng_header_opt_t header = {
        .type   = PCAPNG_OPTION_END,
        .length = 0
    };

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_option_end: write header failed\n");
        return -1;
    }

    return 0;
}

int
pcapng_write_option_string( outfile_t *outfile, uint16_t type, const char *str )
{
    pcapng_header_opt_t header = {
        .type   = type,
        .length = (uint16_t)strlen(str)
    };

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_option_string: write header failed\n");
        return -1;
    }

    if (fwrite(str, 1, header.length, outfile->fp) != header.length) {
        fprintf(stderr, "ERROR: pcapng_write_option_string: write value failed\n");
        return -1;
    }

    return pcapng_write_padding(outfile, header.length);
}

int
pcapng_write_option_uint8( outfile_t *outfile, uint16_t type, uint8_t value )
{
    pcapng_header_opt_t header = {
        .type   = type,
        .length = sizeof(value)
    };

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_option_uint8: write header failed\n");
        return -1;
    }

    if (fwrite(&value, 1, 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_option_uint8: write value failed\n");
        return -1;
    }

    return pcapng_write_padding(outfile, header.length);
}

int
pcapng_write_padding( outfile_t *outfile, size_t datalen )
{
    uint8_t padding[3] = { 0, 0, 0};
    size_t  padlen     = 4 - (datalen % 4);

    if (padlen < 4) {
        if (fwrite(padding, 1, padlen, outfile->fp) != padlen) {
            fprintf(stderr, "ERROR: pcapng_write_padding: write failed\n");
            return -1;
        }
    }

    return 0;
}

int
pcapng_write_section_header_block( outfile_t *outfile, const char* hardware, const char* os, const char* userappl )
{
    pcapng_header_shb_t header = {
        .block_type         = PCAPNG_BLOCK_TYPE_SHB,
        .block_total_length = sizeof(pcapng_header_shb_t),
        .byte_order_magic   = PCAPNG_BYTE_ORDER_MAGIC,
        .version_major      = PCAPNG_VERSION_MAJOR,
        .version_minor      = PCAPNG_VERSION_MINOR,
        .section_length     = PCAPNG_SECTION_LENGTH_UNSPECIFIED
    };

    header.block_total_length += (uint32_t)(hardware != NULL ? sizeof(pcapng_header_opt_t) + roundup(strlen(hardware), 4) : 0);
    header.block_total_length += (uint32_t)(os       != NULL ? sizeof(pcapng_header_opt_t) + roundup(strlen(os),       4) : 0);
    header.block_total_length += (uint32_t)(userappl != NULL ? sizeof(pcapng_header_opt_t) + roundup(strlen(userappl), 4) : 0);
    header.block_total_length += PCAPNG_OPTION_END_TOTAL_LENGTH;
    header.block_total_length += sizeof(header.block_total_length);

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_section_header_block: write header failed\n");
        return -1;
    }

    if (hardware != NULL) {
        if (pcapng_write_option_string(outfile, PCAPNG_SHB_OPTION_HARDWARE, hardware) == -1) {
            return -1;
        }
    }

    if (os != NULL) {
        if (pcapng_write_option_string(outfile, PCAPNG_SHB_OPTION_OS, os) == -1) {
            return -1;
        }
    }

    if (userappl != NULL) {
        if (pcapng_write_option_string(outfile, PCAPNG_SHB_OPTION_USERAPPL, userappl) == -1) {
            return -1;
        }
    }

    if (pcapng_write_option_end(outfile) == -1) {
        return -1;
    }

    if (fwrite(&header.block_total_length, sizeof(header.block_total_length), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcapng_write_section_header_block: write block length failed\n");
        return -1;
    }

    outfile->size += header.block_total_length;

    return pcapng_maybe_flush(outfile);
}
