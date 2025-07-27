/*
 * Copyright (C) 2025 Roger Hunen
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation under the terms of the GNU General Public License is hereby 
 * granted. No representations are made about the suitability of this software 
 * for any purpose. It is provided "as is" without express or implied warranty.
 * See the GNU General Public License for more details.
 */

#ifndef __TZSP2PCAPNG_H__
#define __TZSP2PCAPNG_H__

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

/**************/
/* linktype.c */
/**************/

#define LINKTYPE_ETHERNET   1

const char *linktype_name  ( uint32_t link_type );

/*************/
/* options.c */
/*************/

typedef struct
{
    bool            flush_every_packet;
    struct in6_addr from_addr_inet6;
    bool            legacy_pcap_format;
    uint32_t        link_type;
    char           *outfile_basename;
    uint32_t        outfile_maxage;
    uint32_t        outfile_maxsize;
    char           *pcapng_hardware;
    char           *pcapng_os;
    char           *pcapng_userappl;
    char           *pcapng_interface;
    char           *post_rotate_command;
    int             snaplen;
    in_port_t       tzsp_port;
    bool            verbose;
}
options_t;

extern  int     options_arg2uint32      ( const char *option, const char *optarg, uint32_t min, uint32_t max, uint32_t *value );
extern  void    options_parse_args      ( int argc, char **argv, options_t *options );
extern  void    options_print_summary   ( options_t *options );
extern  void    options_print_usage     ( void );

/*************/
/* outfile.c */
/*************/

#define OUTFILE_MAXAGE_MIN      60          // 1 mminute
#define OUTFILE_MAXAGE_MAX      604800      // 1 week

#define OUTFILE_MAXSIZE_MIN     1024        // 1 kB
#define OUTFILE_MAXSIZE_MAX     UINT32_MAX  // 4 GB - 1 

typedef struct
{
    FILE       *fp;                 // File descriptor
    time_t      creation_time;      // Creation time
    size_t      size;               // File size
    bool        flush_every_packet; // Flush output after every packet
}
outfile_t;

extern  int     outfile_close   ( outfile_t *outfile, options_t *options );
extern  int     outfile_name    ( char *buf, size_t buflen, options_t *options, bool bump_sequence_number );
extern  int     outfile_open    ( outfile_t *outfile, options_t *options );

/**********/
/* pcap.c */
/**********/

#define PCAP_DEFAULT_SNAPLEN        65535

#define PCAP_MAGIC_USEC_PRECISION   0xA1B2C3D4

#define PCAP_VERSION_MAJOR          2
#define PCAP_VERSION_MINOR          4

typedef struct
{
    uint32_t    magic_number;
    uint16_t    version_major;
    uint16_t    version_minor;
    uint32_t    reserved1;  // Must be 0
    uint32_t    reserved2;  // Must be 0
    uint32_t    snaplen;
    uint32_t    link_type;
} __attribute__((packed))
pcap_header_t;

typedef struct
{
    uint32_t    ts_sec;
    uint32_t    ts_usec;
    uint32_t    cap_len;
    uint32_t    org_len;
} __attribute__((packed))
pcap_record_header_t;

extern  int     pcap_maybe_flush    ( outfile_t *outfile );
extern  int     pcap_write_header   ( outfile_t *outfile, uint32_t link_type );
extern  int     pcap_write_packet   ( outfile_t *outfile, const uint8_t* data, size_t datalen, const struct timeval *timestamp );

/************/
/* pcapng.c */
/************/

#define PCAPNG_BLOCK_TYPE_SHB                   0x0a0d0d0a  // Section Header Block
#define PCAPNG_BLOCK_TYPE_IDB                   0x00000001  // Interface Description Block
#define PCAPNG_BLOCK_TYPE_PB                    0x00000002  // Packet Block (obsolete)
#define PCAPNG_BLOCK_TYPE_SPB                   0x00000003  // Simple Packet Block
#define PCAPNG_BLOCK_TYPE_NRB                   0x00000004  // Name Resolution Block
#define PCAPNG_BLOCK_TYPE_ISB                   0x00000005  // Interface Statistics Block
#define PCAPNG_BLOCK_TYPE_EPB                   0x00000006  // Enhanced Packet Block
#define PCAPNG_BLOCK_TYPE_DSB                   0x0000000a  // Decryption Secrets Block
#define PCAPNG_BLOCK_TYPE_CB1                   0x00000bad  // Custom Block
#define PCAPNG_BLOCK_TYPE_CB2                   0x40000bad  // Custom Block

#define PCAPNG_OPTION_END                       0
#define PCAPNG_OPTION_COMMENT                   1

#define PCAPNG_EPB_OPTION_FLAGS                 2
#define PCAPNG_EPB_OPTION_HASH                  3
#define PCAPNG_EPB_OPTION_DROPCOUNT             4
#define PCAPNG_EPB_OPTION_PACKET_ID             5
#define PCAPNG_EPB_OPTION_QUEUE                 6
#define PCAPNG_EPB_OPTION_VERDICT               7
#define PCAPNG_EPB_OPTION_PROCESSID_THREADID    8

#define PCAPNG_IDB_OPTION_NAME                  2
#define PCAPNG_IDB_OPTION_DESCRIPTION           3
#define PCAPNG_IDB_OPTION_IPV4_ADDR             4
#define PCAPNG_IDB_OPTION_IPV6_ADDR             5
#define PCAPNG_IDB_OPTION_MAC_ADDR              6
#define PCAPNG_IDB_OPTION_EUI_ADDR              7
#define PCAPNG_IDB_OPTION_SPEED                 8
#define PCAPNG_IDB_OPTION_TS_RESOLUTION         9
#define PCAPNG_IDB_OPTION_TIMEZONE              10
#define PCAPNG_IDB_OPTION_FILTER                11
#define PCAPNG_IDB_OPTION_OS                    12
#define PCAPNG_IDB_OPTION_FCS_LEN               13
#define PCAPNG_IDB_OPTION_TS_OFFSET             14
#define PCAPNG_IDB_OPTION_HARDWARE              15
#define PCAPNG_IDB_OPTION_TX_SPEED              16
#define PCAPNG_IDB_OPTION_RX_SPEED              17
#define PCAPNG_IDB_OPTION_IANA_TZNAME           18

#define PCAPNG_SHB_OPTION_HARDWARE              2
#define PCAPNG_SHB_OPTION_OS                    3
#define PCAPNG_SHB_OPTION_USERAPPL              4

#define PCAPNG_SECTION_LENGTH_UNSPECIFIED       0xffffffffffffffff
#define PCAPNG_VERSION_MAJOR                    1
#define PCAPNG_VERSION_MINOR                    0

#define PCAPNG_BYTE_ORDER_MAGIC                 0x1a2b3c4d
#define PCAPNG_DEFAULT_SNAPLEN                  0x00040000
#define PCAPNG_OPTION_END_TOTAL_LENGTH          sizeof(pcapng_header_opt_t)
#define PCAPNG_OPTION_UINT8_TOTAL_LENGTH       (sizeof(pcapng_header_opt_t) + 4)
#define PCAPNG_TS_RESOLUTION_USEC               6
#define PCAPNG_TS_RESOLUTION_NSEC               9

typedef struct {
    uint32_t    block_type;
    uint32_t    block_total_length;
    uint32_t    interface_id;
    uint32_t    timestamp_upper;
    uint32_t    timestamp_lower;
    uint32_t    cap_len;
    uint32_t    org_len;    
} __attribute__((packed))
pcapng_header_epb_t;

typedef struct {
    uint32_t    block_type;
    uint32_t    block_total_length;
    uint16_t    link_type;
    uint16_t    reserved1;  // Must be 0
    uint32_t    snaplen;
} __attribute__((packed))
pcapng_header_idb_t;

typedef struct {
    uint16_t    type;
    uint16_t    length;
} __attribute__((packed))
pcapng_header_opt_t;

typedef struct {
    uint32_t    block_type;
    uint32_t    block_total_length;
    uint32_t    byte_order_magic;
    uint16_t    version_major;
    uint16_t    version_minor;
    uint64_t    section_length;
} __attribute__((packed))
pcapng_header_shb_t;

extern  int         pcapng_maybe_flush                          ( outfile_t *outfile );
extern  uint64_t    pcapng_timestamp                            ( struct timeval *timestamp, int resolution );
extern  int         pcapng_write_enhanced_packet_block          ( outfile_t *outfile, const uint8_t* data, size_t datalen, uint64_t timestamp );
extern  int         pcapng_write_interface_description_block    ( outfile_t *outfile, const char* name, const char* description, uint16_t link_type, uint8_t ts_resolution );
extern  int         pcapng_write_option_end                     ( outfile_t *outfile );
extern  int         pcapng_write_option_string                  ( outfile_t *outfile, uint16_t type, const char *str );
extern  int         pcapng_write_option_uint8                   ( outfile_t *outfile, uint16_t type, uint8_t value );
extern  int         pcapng_write_padding                        ( outfile_t *outfile, size_t datalen );
extern  int         pcapng_write_section_header_block           ( outfile_t *outfile, const char* hardware, const char* os, const char* userappl );

/**********/
/* tzsp.c */
/**********/

#define TZSP_DATA_RATE_1000             2
#define TZSP_DATA_RATE_2000             4
#define TZSP_DATA_RATE_5500             11
#define TZSP_DATA_RATE_6000             12
#define TZSP_DATA_RATE_9000             18
#define TZSP_DATA_RATE_11000            22
#define TZSP_DATA_RATE_12000            24
#define TZSP_DATA_RATE_18000            36
#define TZSP_DATA_RATE_22000            44
#define TZSP_DATA_RATE_24000            48
#define TZSP_DATA_RATE_33000            66
#define TZSP_DATA_RATE_36000            72
#define TZSP_DATA_RATE_48000            96
#define TZSP_DATA_RATE_54000            108

#define TZSP_DATA_RATE_1000_OLD         10
#define TZSP_DATA_RATE_2000_OLD         20
#define TZSP_DATA_RATE_5500_OLD         55
#define TZSP_DATA_RATE_11000_OLD        110

#define TZSP_DEFAULT_LISTEN_PORT        37008

#define TZSP_TAG_PADDING                0
#define TZSP_TAG_END                    1
#define TZSP_TAG_RAW_RSSI               10
#define TZSP_TAG_SNR                    11
#define TZSP_TAG_DATA_RATE              12
#define TZSP_TAG_TIMESTAMP              13
#define TZSP_TAG_CONTENTION_FREE        15
#define TZSP_TAG_DECRYPTED              16
#define TZSP_TAG_FCS_ERROR              17
#define TZSP_TAG_RX_CHANNEL             18
#define TZSP_TAG_PACKET_COUNT           40
#define TZSP_TAG_RX_FRAME_LENGTH        41
#define TZSP_TAG_WLAN_RADIO_HDR_SERIAL  60

#define TZSP_TYPE_RECEIVED_PACKET       0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT   1
#define TZSP_TYPE_RESERVED              2
#define TZSP_TYPE_CONFIGURATION         3
#define TZSP_TYPE_KEEPALIVE             4
#define TZSP_TYPE_PORT_OPENER           5

typedef struct {
    uint8_t         version;
	uint8_t         type;
	uint16_t        link_type;
} __attribute__((packed))
tzsp_header_t;

typedef struct {
    uint32_t        type;
    uint32_t        link_type;
    struct timeval  timestamp;
    uint8_t         sender_buf[sizeof(struct sockaddr_in6)];
    size_t          payload_offset;
    size_t          payload_length;
}
tzsp_msginfo_t;

typedef struct {
	uint8_t         type;
	uint8_t         data_length;
	uint8_t         data[];
} __attribute__((packed))
tzsp_tag_t;

extern  void        tzsp_close      ( int fd );
extern  int         tzsp_open       ( in_port_t port );
extern  int         tzsp_receive    ( int fd, uint8_t *buf, size_t buflen, tzsp_msginfo_t *msginfo, options_t *options );
extern  const char *tzsp_tag_name   ( uint32_t tag );
extern  const char *tzsp_type_name  ( uint32_t type );

#endif // __TZSP2PCAPNG_H__
