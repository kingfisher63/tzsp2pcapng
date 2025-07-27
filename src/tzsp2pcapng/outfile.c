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

#include <limits.h>

int
outfile_close( outfile_t *outfile, options_t *options )
{
    if (outfile->fp != NULL && outfile->fp != stdout) {
        if (fclose(outfile->fp) == EOF) {
            perror("ERROR: outfile_close: fclose");
            return -1;
        }

        if (options->verbose) {
            fprintf(stderr, "Closed output file, size=%zu\n", outfile->size);
        }
    }

    outfile->fp = NULL;

    return 0;
}

int
outfile_name( char* buf, size_t buflen, options_t *options, bool bump_sequence_number )
{
    static int  sequence_number = 0;

    const char *template = sequence_number > 0 ? "%s.%d" : "%s";
    if (snprintf(buf, buflen, template, options->outfile_basename, sequence_number) >= (int)buflen) {
        fprintf(stderr, "ERROR: outfile_name: output filename length exceeds buffer length (%zu)\n", buflen);
        return -1;
    }

    if (bump_sequence_number && (options->outfile_maxage != 0 || options->outfile_maxsize != 0)) {
        sequence_number++;
    }

    return 0;
}

int
outfile_open( outfile_t *outfile, options_t *options )
{
    char    filename[PATH_MAX];

    if (options->outfile_basename != NULL) {
        if (outfile_name(filename, sizeof(filename), options, true ) < 0) {
            return -1;
        }

        outfile->fp = fopen(filename, "w");
        if (outfile->fp == NULL) {
            perror("ERROR: outfile_open: fopen");
            return -1;
        }

        if (options->verbose) {
            fprintf(stderr, "Opened output file '%s'\n", filename);
        }
    } else {
        outfile->fp = stdout;
    }

    outfile->creation_time      = time(NULL);
    outfile->size               = 0;
    outfile->flush_every_packet = options->flush_every_packet;

    return 0;
}
