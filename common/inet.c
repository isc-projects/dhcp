/* inet.c

   Subroutines to manipulate internet addresses in a safely portable
   way... */

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
"$Id: inet.c,v 1.7 1999/04/23 22:07:38 mellon Exp $ Copyright (c) 1995, 1996, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/* Return just the network number of an internet address... */

struct iaddr subnet_number (addr, mask)
	struct iaddr addr;
	struct iaddr mask;
{
	int i;
	struct iaddr rv;

	rv.len = 0;

	/* Both addresses must have the same length... */
	if (addr.len != mask.len)
		return rv;

	rv.len = addr.len;
	for (i = 0; i < rv.len; i++)
		rv.iabuf [i] = addr.iabuf [i] & mask.iabuf [i];
	return rv;
}

/* Combine a network number and a integer to produce an internet address.
   This won't work for subnets with more than 32 bits of host address, but
   maybe this isn't a problem. */

struct iaddr ip_addr (subnet, mask, host_address)
	struct iaddr subnet;
	struct iaddr mask;
	u_int32_t host_address;
{
	int i, j, k;
	u_int32_t swaddr;
	struct iaddr rv;
	unsigned char habuf [sizeof swaddr];

	swaddr = htonl (host_address);
	memcpy (habuf, &swaddr, sizeof swaddr);

	/* Combine the subnet address and the host address.   If
	   the host address is bigger than can fit in the subnet,
	   return a zero-length iaddr structure. */
	rv = subnet;
	j = rv.len - sizeof habuf;
	for (i = sizeof habuf - 1; i >= 0; i--) {
		if (mask.iabuf [i + j]) {
			if (habuf [i] > (mask.iabuf [i + j] ^ 0xFF)) {
				rv.len = 0;
				return rv;
			}
			for (k = i - 1; k >= 0; k--) {
				if (habuf [k]) {
					rv.len = 0;
					return rv;
				}
			}
			rv.iabuf [i + j] |= habuf [i];
			break;
		} else
			rv.iabuf [i + j] = habuf [i];
	}
		
	return rv;
}

/* Given a subnet number and netmask, return the address on that subnet
   for which the host portion of the address is all ones (the standard
   broadcast address). */

struct iaddr broadcast_addr (subnet, mask)
	struct iaddr subnet;
	struct iaddr mask;
{
	int i, j, k;
	struct iaddr rv;

	if (subnet.len != mask.len) {
		rv.len = 0;
		return rv;
	}

	for (i = 0; i < subnet.len; i++) {
		rv.iabuf [i] = subnet.iabuf [i] | (~mask.iabuf [i] & 255);
	}
	rv.len = subnet.len;

	return rv;
}

u_int32_t host_addr (addr, mask)
	struct iaddr addr;
	struct iaddr mask;
{
	int i;
	u_int32_t swaddr;
	struct iaddr rv;

	rv.len = 0;

	/* Mask out the network bits... */
	rv.len = addr.len;
	for (i = 0; i < rv.len; i++)
		rv.iabuf [i] = addr.iabuf [i] & ~mask.iabuf [i];

	/* Copy out up to 32 bits... */
	memcpy (&swaddr, &rv.iabuf [rv.len - sizeof swaddr], sizeof swaddr);

	/* Swap it and return it. */
	return ntohl (swaddr);
}

int addr_eq (addr1, addr2)
	struct iaddr addr1, addr2;
{
	if (addr1.len != addr2.len)
		return 0;
	return memcmp (addr1.iabuf, addr2.iabuf, addr1.len) == 0;
}

char *piaddr (addr)
	struct iaddr addr;
{
	static char pbuf [4 * 16];
	char *s = pbuf;
	int i;

	if (addr.len == 0) {
		strcpy (s, "<null address>");
	}
	for (i = 0; i < addr.len; i++) {
		sprintf (s, "%s%d", i ? "." : "", addr.iabuf [i]);
		s += strlen (s);
	}
	return pbuf;
}
