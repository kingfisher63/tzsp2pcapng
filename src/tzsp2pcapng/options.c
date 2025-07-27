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

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

inline static bool
delete_string( char **pp )
{
    if (pp != NULL && *pp != NULL) {
        free(*pp); *pp = NULL;
        return true;
    }

    return false;
}

int
options_arg2uint32( const char *option, const char *optarg, uint32_t min, uint32_t max, uint32_t *value )
{
    char   *endptr;

    long unsigned int val = strtoul(optarg, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "ERROR: invalid argument '%s' for option '%s'\n", optarg, option);
        return -1;
    }

    if (val < min || val > max) {
        fprintf(stderr, "ERROR: argument '%s' out of range for option '%s' (range %u-%u)\n", optarg, option, min, max);
        return -1;
    }

   *value = (uint32_t)val;
    return 0;
}

void
options_parse_args( int argc, char **argv, options_t *options )
{
    int         ch;
    uint32_t    argval;
    char        buf[512];

    memset(options, 0, sizeof(options_t));
    options->link_type      = LINKTYPE_ETHERNET;
    options->tzsp_port      = TZSP_DEFAULT_LISTEN_PORT;

    while ((ch = getopt(argc, argv, "C:fF:G:hH:I:O:Pp:vw:z:")) != -1) {
        switch(ch) {
            case 'C':
                if (options_arg2uint32("C", optarg, OUTFILE_MAXSIZE_MIN, OUTFILE_MAXSIZE_MAX, &options->outfile_maxsize) < 0) {
                    exit(1);
                }
                break;

            case 'f':
                options->flush_every_packet = true;
                break;

            case 'F':
                if (inet_pton(AF_INET6, optarg, &options->from_addr_inet6) == 1) {
                    break;
                }

                in_addr_t addr_inet;
                if (inet_pton(AF_INET, optarg, &addr_inet) == 1) {
                    options->from_addr_inet6.s6_addr32[0] = 0,
                    options->from_addr_inet6.s6_addr32[1] = 0,
                    options->from_addr_inet6.s6_addr32[2] = htonl(0x0000ffff);
                    options->from_addr_inet6.s6_addr32[3] = addr_inet;
                    break;
                }

                fprintf(stderr, "ERROR: invalid IP address '%s'\n", optarg);
                exit (1);

            case 'G':
                if (options_arg2uint32("G", optarg, OUTFILE_MAXAGE_MIN, OUTFILE_MAXAGE_MAX, &options->outfile_maxage) < 0) {
                    exit(1);
                }
                break;

            case 'h':
                options_print_usage();
                exit(0);

            case 'H':
                delete_string(&options->pcapng_hardware);
                options->pcapng_hardware = strdup(optarg);
                break;

            case 'I':
                delete_string(&options->pcapng_interface);
                options->pcapng_interface = strdup(optarg);
                break;

            case 'O':
                delete_string(&options->pcapng_os);
                options->pcapng_os = strdup(optarg);
                break;

            case 'P':
                options->legacy_pcap_format = true;
                break;

            case 'p':
                if (options_arg2uint32("p", optarg, 1, 65535, &argval) < 0) {
                    exit(1);
                }
                options->tzsp_port = (in_port_t)argval;
                break;
            
            case 'v':
                options->verbose = true;
                break;

            case 'w':
                delete_string(&options->outfile_basename);
                options->outfile_basename = strdup(optarg);
                break;

            case 'z':
                delete_string(&options->post_rotate_command);
                options->post_rotate_command = strdup(optarg);
                break;

            default:
                exit(1);
        }
    }

    if (options->outfile_basename != NULL && strcmp(options->outfile_basename, "-") == 0) {
        delete_string(&options->outfile_basename);
    }

    if (options->outfile_maxsize != 0 && options->outfile_basename == NULL) {
        fprintf(stderr, "WARNING: file rotation (-C) requires a regular output file (DISCARDED)\n");
        options->outfile_maxsize = 0;
    }
    if (options->outfile_maxage != 0 && options->outfile_basename == NULL) {
        fprintf(stderr, "WARNING: file rotation (-G) requires a regular output file (DISCARDED)\n");
        options->outfile_maxage = 0;
    }
    if (options->post_rotate_command != NULL && options->outfile_maxage == 0 && options->outfile_maxsize == 0) {
        fprintf(stderr, "WARNING: post rotate command (-z) requires output file rotation (DISCARDED)\n");
        delete_string(&options->post_rotate_command);
    }

    if (options->legacy_pcap_format) {
        if (delete_string(&options->pcapng_hardware)) {
            fprintf(stderr, "WARNING: option -H is not valid for legacy Pcap format (DISCARDED)\n");
        }
        if (delete_string(&options->pcapng_interface)) {
            fprintf(stderr, "WARNING: option -I is not valid for legacy Pcap format (DISCARDED)\n");
        }
        if (delete_string(&options->pcapng_os)) {
            fprintf(stderr, "WARNING: option -O is not valid for legacy Pcap format (DISCARDED)\n");
        }
    } else {
        if (options->pcapng_hardware == NULL) {
            FILE *fp = fopen("/proc/cpuinfo", "r");
            if (fp == NULL) {
                perror("ERROR: pcapng_init: /proc/cpuinfo");
                exit(1);
            }

            while (fgets(buf, sizeof(buf), fp) != NULL) {
                for (size_t len = strlen(buf); len > 0 && isspace(buf[len-1]); len--) {
                    buf[len-1] = '\0';
                }

                if (strstr(buf, "model name") == buf) {
                    char *p = strstr(buf, ":");
                    if (p != NULL) {
                        options->pcapng_hardware = strdup(p+2);
                        break;
                    }
                }
            }

            fclose(fp);
        }

        if (options->pcapng_os == NULL) {
            struct utsname  name;

            if (uname (&name) == -1) {
                perror("ERROR: uname");
                exit(1);
            }

            snprintf(buf, sizeof(buf), "%s %s %s %s", name.sysname, name.release, name.version, name.machine);
            options->pcapng_os = strdup(buf);
        }

        if (options->pcapng_userappl == NULL) {
            snprintf(buf, sizeof(buf), "%s v%s", PROGRAM_NAME, PROGRAM_VERSION);
            options->pcapng_userappl = strdup(buf);
        }

        if (options->pcapng_interface == NULL) {
            options->pcapng_interface = strdup(linktype_name(options->link_type));
        }
    }

    if (options->verbose) {
        options_print_summary(options);
    }
}

void
options_print_summary( options_t *options )
{
    fprintf(stderr, "Options summary\n");

    // Capture

    fprintf(stderr, "- Listen UDP port: %u\n", options->tzsp_port);

    // Output

    if (options->outfile_basename != NULL) {
        fprintf(stderr, "- Write data to file: %s\n", options->outfile_basename);
    } else {
        fprintf(stderr, "- Write data to stdout\n");
    }
    if (options->legacy_pcap_format) {
        fprintf(stderr, "- Data format: legacy Pcap\n");
    } else {
        fprintf(stderr, "- Data format: PcapNG\n");
    }
    if (options->outfile_maxsize != 0) {
        fprintf(stderr, "- Rotate output file after %u bytes\n", options->outfile_maxsize);
    }
    if (options->outfile_maxage != 0) {
        fprintf(stderr, "- Rotate output file after %u seconds\n", options->outfile_maxage);
    }
    if (options->post_rotate_command != NULL) {
        fprintf(stderr, "- Post rotate commmand: %s\n", options->post_rotate_command);
    }
    fprintf(stderr, "- Flush data after every packet: %s\n", options->flush_every_packet ? "yes" : "no");

    // PcapNG only

    if (!options->legacy_pcap_format) {
        fprintf(stderr, "- Capture hardware: %s\n", options->pcapng_hardware);
        fprintf(stderr, "- Capture OS: %s\n", options->pcapng_os);
        fprintf(stderr, "- Capture application: %s\n", options->pcapng_userappl);
        fprintf(stderr, "- Capture interface: %s\n", options->pcapng_interface);
    }
}

void
options_print_usage( void )
{
    fprintf(stderr, 
        "%s v%s - TZSP (TaZmen Sniffer Protocol) to PcapNG converter\n"
        "\n"
        "Options:\n"
        "  -C file_size         Rotate output file after file_size bytes (range %u-%u)\n"
        "  -f                   Flush output after every packet\n"
        "  -F ip_address        Accept only TZSP messages from ip_address\n"
        "  -G file_age          Rotate output file after file_age seconds (range %u-%u)\n"
        "  -h                   Print this message and exit\n"
        "  -H hardware          Capture hardware (PcapNG only)\n"
        "  -I interface         Capture interface (PcapNG only)\n"
        "  -O operating_system  Capture operating system (PcapNG only)\n"
        "  -p port              UDP port to listen on (default: %u)\n"
        "  -P                   Write legacy Pcap format\n"
        "  -v                   Print verbose information on stderr\n"
        "  -w file              Write data to a file ('-' = stdout)\n"
        "  -z command           Run command after output file rotation\n",
        PROGRAM_NAME, PROGRAM_VERSION,
        OUTFILE_MAXSIZE_MIN, OUTFILE_MAXSIZE_MAX,
        OUTFILE_MAXAGE_MIN, OUTFILE_MAXAGE_MAX,
        TZSP_DEFAULT_LISTEN_PORT
    );
}
