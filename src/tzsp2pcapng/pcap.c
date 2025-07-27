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

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

int
pcap_maybe_flush( outfile_t *outfile )
{
    if (outfile->flush_every_packet) {
        if (fflush(outfile->fp) == EOF) {
            perror("ERROR: pcap_maybe_flush");
            return -1;
        }
    }

    return 0;
}

int
pcap_write_header( outfile_t *outfile, uint32_t link_type )
{
    pcap_header_t header = {
        .magic_number  = PCAP_MAGIC_USEC_PRECISION,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .reserved1     = 0,
        .reserved2     = 0,
        .snaplen       = PCAP_DEFAULT_SNAPLEN,
        .link_type     = link_type
    };

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcap_write_header: write header failed\n");
        return -1;
    }

    outfile->size += sizeof(header);

    return pcap_maybe_flush(outfile);
}

int
pcap_write_packet( outfile_t *outfile, const uint8_t* data, size_t datalen, const struct timeval *timestamp )
{
    size_t caplen = MIN(datalen, PCAP_DEFAULT_SNAPLEN);

    pcap_record_header_t header = {
        .ts_sec  = (uint32_t)timestamp->tv_sec,
        .ts_usec = (uint32_t)timestamp->tv_usec,
        .cap_len = (uint32_t)caplen,
        .org_len = (uint32_t)datalen
    };

    if (fwrite(&header, sizeof(header), 1, outfile->fp) != 1) {
        fprintf(stderr, "ERROR: pcap_write_packet: write header failed\n");
        return -1;
    }

    if (fwrite(data, 1, caplen, outfile->fp) != caplen) {
        fprintf(stderr, "ERROR: pcap_write_packet: fwrite pacet data failed\n");
        return -1;
    }

    outfile->size += sizeof(header) + caplen;

    return pcap_maybe_flush(outfile);
}
