/* packet.c

   Packet assembly code, originally contributed by Archie Cobbs. */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef lint
static char copyright[] =
"$Id: ethernet.c,v 1.1 1999/05/27 17:34:54 mellon Exp $ Copyright (c) 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined (PACKET_ASSEMBLY) || defined (PACKET_DECODING)
#include "includes/netinet/if_ether.h"
#endif /* PACKET_ASSEMBLY || PACKET_DECODING */

#if defined (PACKET_ASSEMBLY)
/* Assemble an hardware header... */
/* XXX currently only supports ethernet; doesn't check for other types. */

void assemble_ethernet_header (interface, buf, bufix, to)
	struct interface_info *interface;
	unsigned char *buf;
	int *bufix;
	struct hardware *to;
{
	struct ether_header eh;

	if (to && to -> hlen == 6) /* XXX */
		memcpy (eh.ether_dhost, to -> haddr, sizeof eh.ether_dhost);
	else
		memset (eh.ether_dhost, 0xff, sizeof (eh.ether_dhost));
	if (interface -> hw_address.hlen == sizeof (eh.ether_shost))
		memcpy (eh.ether_shost, interface -> hw_address.haddr,
			sizeof (eh.ether_shost));
	else
		memset (eh.ether_shost, 0x00, sizeof (eh.ether_shost));

#ifdef BROKEN_FREEBSD_BPF /* Fixed in FreeBSD 2.2 */
	eh.ether_type = ETHERTYPE_IP;
#else
	eh.ether_type = htons (ETHERTYPE_IP);
#endif

	memcpy (&buf [*bufix], &eh, sizeof eh);
	*bufix += sizeof eh;
}
#endif /* PACKET_ASSEMBLY */

#ifdef PACKET_DECODING
/* Decode a hardware header... */

ssize_t decode_ethernet_header (interface, buf, bufix, from)
     struct interface_info *interface;
     unsigned char *buf;
     int bufix;
     struct hardware *from;
{
  struct ether_header eh;

  memcpy (&eh, buf + bufix, sizeof eh);

#ifdef USERLAND_FILTER
  if (ntohs (eh.ether_type) != ETHERTYPE_IP)
	  return -1;
#endif
  memcpy (from -> haddr, eh.ether_shost, sizeof (eh.ether_shost));
  from -> htype = ARPHRD_ETHER;
  from -> hlen = sizeof eh.ether_shost;

  return sizeof eh;
}
#endif /* PACKET_DECODING */
