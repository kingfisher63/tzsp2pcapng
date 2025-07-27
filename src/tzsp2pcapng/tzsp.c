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
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static inline bool
in6equal( const struct in6_addr *a1, const struct in6_addr *a2 ) {
    return  a1->s6_addr32[0] == a2->s6_addr32[0] &&
            a1->s6_addr32[1] == a2->s6_addr32[1] &&
            a1->s6_addr32[2] == a2->s6_addr32[2] &&
            a1->s6_addr32[3] == a2->s6_addr32[3];
}

void
tzsp_close( int fd ) {
    close(fd);
}

static char *
tzsp_inet_ntop( struct sockaddr *addr )
{
    if (addr->sa_family == AF_INET) {
        static char buf[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop");
            return "UNKOWN";
        }

        return buf;
    }

    if (addr->sa_family == AF_INET6) {
        static char buf[INET6_ADDRSTRLEN];

        if (inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf)) == NULL) {
            perror("inet_ntop");
            return "UNKOWN";
        }

        return strncasecmp(buf, "::ffff:", 7) == 0 ? buf+7 : buf;
    }

    return "UNKOWN";
}


int
tzsp_open( in_port_t port )
{
    int sock_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_fd == -1) {
        perror("ERROR: socket");
        return -1;
    }

    int opt_val = 0;
    if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&opt_val, sizeof(opt_val)) == -1) {
        perror("ERROR: setsockopt");
        close(sock_fd);
        return -1;
    }

    struct sockaddr_in6 listen_address = {
        #ifdef SIN6_LEN
		.sin6_len      = sizeof(struct sockaddr_in6),
		#endif
        .sin6_family   = AF_INET6,
        .sin6_port     = htons(port),
        .sin6_flowinfo = 0,
        .sin6_addr     = in6addr_any,
        .sin6_scope_id = 0
    };

    if (bind(sock_fd, (struct sockaddr*)&listen_address, sizeof(listen_address)) == -1) {
        perror("ERROR: bind");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int
tzsp_receive( int sock_fd, uint8_t *buf, size_t buflen, tzsp_msginfo_t *msginfo, options_t *options )
{
   /*
    * Receive message
    */

    socklen_t   sender_buf_size = sizeof(msginfo->sender_buf);
    ssize_t     length          = recvfrom(sock_fd, buf, buflen, 0, (struct sockaddr *)msginfo->sender_buf, &sender_buf_size);

    if (length < 0) {
        if (errno != EINTR) {
            perror("ERROR: recvfrom");
        }

        return -1;
    }

    gettimeofday(&msginfo->timestamp, NULL);

    struct sockaddr *sender = (struct sockaddr *)msginfo->sender_buf;

    // Note: TZSP traffic from IPv4 senders is received as IPv4-mapped IPv6.

    if (sender->sa_family != AF_INET6) {
        fprintf(stderr, "WARNING: sender address family (%d) not supported [packet discarded]\n", sender->sa_family);
        errno = EINTR;
        return -1;
    }

    if (options->verbose) {
        fprintf(stderr, "Received %zd bytes from %s\n", length, tzsp_inet_ntop(sender));
    }

    if (!in6equal(&options->from_addr_inet6, &in6addr_any)) {
        if (!in6equal(&options->from_addr_inet6, &((struct sockaddr_in6 *)sender)->sin6_addr)) {
            if (options->verbose) {
                fprintf(stderr, "Sender address not allowed [packet discarded]\n");
            }

            errno = EINTR;
            return -1;
        }
    }

    /*
    * Decode message
    */

    const uint8_t  *p = buf;            // Message pointer
    size_t          n = (size_t)length; // Message bytes left

    // Header

    if (n < sizeof(tzsp_header_t)) {
        fprintf(stderr, "ERROR: truncated TZSP header)\n");
        return -1;
    }

    tzsp_header_t *tzsp_header = (tzsp_header_t *)p;
    if (tzsp_header->version != 1) {
        fprintf(stderr, "ERROR: invalid TZSP version (%u)\n", tzsp_header->version);
        return -1;
    }

    msginfo->type =            tzsp_header->type;
    msginfo->link_type = ntohs(tzsp_header->link_type);

    if (options->verbose) {
        fprintf(stderr, "- Hdr: type=%s(%u) link_type=%s(%u)\n",
            tzsp_type_name(msginfo->type),      msginfo->type,
            linktype_name (msginfo->link_type), msginfo->link_type
        );
    }

    p += sizeof(tzsp_header_t);
    n -= sizeof(tzsp_header_t);

    // Tags

    while (true) {
        if (n < 1) {
            fprintf(stderr, "ERROR: truncated TZSP tag list\n");
            return -1;
        }

        tzsp_tag_t *tzsp_tag = (tzsp_tag_t *)p;
        size_t      taglen;

        switch (tzsp_tag->type) {
            case TZSP_TAG_PADDING :
            case TZSP_TAG_END :
                taglen = 1;
                break;

            default:
                if (n < sizeof(tzsp_tag_t)) {
                    fprintf(stderr, "ERROR: truncated TZSP tag\n");
                    return -1;
                }

                taglen = sizeof(tzsp_tag_t) + tzsp_tag->data_length;
                if (n < taglen) {
                    fprintf(stderr, "ERROR: truncated TZSP tag\n");
                    return -1;
                }
                break;
        }

        if (options->verbose) {
            fprintf(stderr, "- Tag: type=%s(%u) length=%zu\n",
                tzsp_tag_name(tzsp_tag->type), tzsp_tag->type,
                taglen
            );
        }

        p += taglen;
        n -= taglen;

        if (tzsp_tag->type == TZSP_TAG_END) {
            break;
        }
    }

    // Payload

    msginfo->payload_offset = (size_t)length - n;
    msginfo->payload_length = n;

    if (options->verbose) {
        fprintf(stderr, "- Payload: offset=%zu length=%zu\n",
            msginfo->payload_offset,
            msginfo->payload_length
        );
    }

    return 0;
}

const char *
tzsp_tag_name( uint32_t tag )
{
    switch (tag) {
        case TZSP_TAG_PADDING               : return "PADDING";
        case TZSP_TAG_END                   : return "END";
        case TZSP_TAG_RAW_RSSI              : return "RAW_RSSI";
        case TZSP_TAG_SNR                   : return "SNR";
        case TZSP_TAG_DATA_RATE             : return "DATA_RATE";
        case TZSP_TAG_TIMESTAMP             : return "TIMESTAMP";
        case TZSP_TAG_CONTENTION_FREE       : return "CONTENTION_FREE";
        case TZSP_TAG_DECRYPTED             : return "DECRYPTED";
        case TZSP_TAG_FCS_ERROR             : return "FCS_ERROR";
        case TZSP_TAG_RX_CHANNEL            : return "RX_CHANNEL";
        case TZSP_TAG_PACKET_COUNT          : return "PACKET_COUNT";
        case TZSP_TAG_RX_FRAME_LENGTH       : return "RX_FRAME_LENGTH";
        case TZSP_TAG_WLAN_RADIO_HDR_SERIAL : return "RADIO_HDR_SERIAL";
        default                             : return "UNKNOWN";
    }
}

const char *
tzsp_type_name( uint32_t type )
{
    switch (type) {
        case TZSP_TYPE_RECEIVED_PACKET     : return "RECEIVED_PACKET";
        case TZSP_TYPE_PACKET_FOR_TRANSMIT : return "PACKET_FOR_TRANSMIT";
        case TZSP_TYPE_RESERVED            : return "RESERVED";
        case TZSP_TYPE_CONFIGURATION       : return "CONFIGURATION";
        case TZSP_TYPE_KEEPALIVE           : return "KEEPALIVE";
        case TZSP_TYPE_PORT_OPENER         : return "PORT_OPENER";
        default                            : return "UNKNOWN";
    }
}
