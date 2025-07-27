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

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

static  bool    stop_recording = false;

static  void    run_post_rotate_command ( options_t *options );
static  void    signal_handler          ( int signum );
static  int     write_headers           ( outfile_t *outfile, options_t *options );

int
main( int argc, char **argv )
{
    options_t       options;
    outfile_t       outfile;
    uint8_t         tzsp_msgbuf[65536];
    tzsp_msginfo_t  tzsp_msginfo;

    options_parse_args(argc, argv, &options);

    struct sigaction new_action = {
        .sa_handler = signal_handler,
        .sa_flags   = 0,
    };

    sigemptyset(&new_action.sa_mask);
    sigaction(SIGINT,  &new_action, NULL);
    sigaction(SIGTERM, &new_action, NULL);

    int tzsp_fd = tzsp_open(options.tzsp_port);
    if (tzsp_fd == -1) {
        goto on_error_tzsp_open;
    }

    if (outfile_open(&outfile, &options) < 0 || write_headers(&outfile, &options) < 0) {
        goto on_error_outfile_open;
    }

    while (1) {
        if (stop_recording) {
            if (options.verbose) {
                fprintf(stderr, "Caught signal, exiting\n");
            }
            break;
        }

        if (tzsp_receive(tzsp_fd, tzsp_msgbuf, sizeof(tzsp_msgbuf), &tzsp_msginfo, &options) < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                break;
            }
        }

        // Some sniffers send captured packets as "Transmit", so we will accept this message type too.
        if (tzsp_msginfo.type != TZSP_TYPE_RECEIVED_PACKET && tzsp_msginfo.type != TZSP_TYPE_PACKET_FOR_TRANSMIT) {
            if (options.verbose) {
                fprintf(stderr, "Unsupported TZSP message type %u (%s) [SKIPPED]\n", tzsp_msginfo.type, tzsp_type_name(tzsp_msginfo.type));
            }
            continue;
        }

        if (tzsp_msginfo.link_type != options.link_type) {
            if (options.verbose) {
                fprintf(stderr, "Unsupported link type %u (%s) [SKIPPED]\n", tzsp_msginfo.link_type, linktype_name(tzsp_msginfo.link_type));
            }
            continue;
        }

        if (options.legacy_pcap_format) {
            pcap_write_packet(
                &outfile, tzsp_msgbuf+tzsp_msginfo.payload_offset, tzsp_msginfo.payload_length, &tzsp_msginfo.timestamp
            );
        } else {
            pcapng_write_enhanced_packet_block(
                &outfile, tzsp_msgbuf+tzsp_msginfo.payload_offset, tzsp_msginfo.payload_length, pcapng_timestamp(&tzsp_msginfo.timestamp, PCAPNG_TS_RESOLUTION_USEC)
            );
        }

        bool rotate = false;

        if (options.outfile_maxage  != 0 && tzsp_msginfo.timestamp.tv_sec - outfile.creation_time >= options.outfile_maxage) {
            if (options.verbose) {
                fprintf(stderr, "Maximum file age exceeded, rotating output file\n");
            }
            rotate = true;
        } else
        if (options.outfile_maxsize != 0 && outfile.size >= options.outfile_maxsize) {
            if (options.verbose) {
                fprintf(stderr, "Maximum file size exceeded, rotating output file\n");
            }
            rotate = true;
        }

        if (rotate) {
            if (outfile_close(&outfile, &options) < 0) {
                goto on_error_outfile_close;
            }

            run_post_rotate_command(&options);

            if (outfile_open(&outfile, &options) < 0 || write_headers(&outfile, &options) < 0) {
                goto on_error_outfile_open;
            }
        }
    }

    outfile_close(&outfile, &options);
    tzsp_close(tzsp_fd);

    exit(0);

on_error_outfile_close:
on_error_outfile_open:
    tzsp_close(tzsp_fd);

on_error_tzsp_open:
    exit(1);
}

static  void
run_post_rotate_command( options_t *options )
{
    char filename[PATH_MAX];

    if (options->post_rotate_command == NULL) {
        return;
    }
    if (outfile_name(filename, sizeof(filename), options, false) < 0) {
        return;
    }

    if (options->verbose) {
        fprintf(stderr, "Running post-rotate command: %s\n", options->post_rotate_command);
    }

    switch (fork()) {
        case -1:    // Fork failed
            perror("ERROR: run_post_rotate_command: fork");
            return;

        case 0:     // Child process
            setpriority(PRIO_PROCESS, 0, 19);
            execlp(options->post_rotate_command, options->post_rotate_command, filename, NULL);
            perror("ERROR: run_post_rotate_command: execlp");
            exit(1);

        default:    // Parent process
            return;
    }
}

static void
signal_handler( int signum )
{
    signal(signum, SIG_DFL);

    stop_recording = true;
}

static int
write_headers( outfile_t *outfile, options_t *options )
{
    if (options->legacy_pcap_format) {
        if (pcap_write_header(outfile, options->link_type) < 0) {
            return -1;
        }
    } else {
        if (pcapng_write_section_header_block(outfile, options->pcapng_hardware, options->pcapng_os, options->pcapng_userappl) < 0) {
            return -1;
        }
        if (pcapng_write_interface_description_block(outfile, "TZSP", options->pcapng_interface, (uint16_t)options->link_type, PCAPNG_TS_RESOLUTION_USEC) < 0) {
            return -1;
        }
    }

    return 0;
}
