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

const char *
linktype_name( uint32_t link_type )
{
    switch (link_type) {
        case LINKTYPE_ETHERNET: return "Ethernet";
        default:                return "Unknown";
    }
}
