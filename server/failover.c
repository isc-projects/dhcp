/* failover.c

   Failover protocol support code... */

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
"$Id: failover.c,v 1.2 1999/03/16 05:50:46 mellon Exp $ Copyright (c) 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined (FAILOVER_PROTOCOL)
static struct hash_table *failover_hash;

void enter_failover_peer (peer)
	struct failover_peer *peer;
{
	add_hash (failover_hash, peer -> name, 0, (unsigned char *)peer);
}

struct failover_peer *find_failover_peer (name)
	char *name;
{
	struct failover_peer *peer;

	peer = ((struct failover_peer *)
		hash_lookup (failover_hash, peer -> name, 0));
	return peer;
}

#endif /* defined (FAILOVER_PROTOCOL) */
