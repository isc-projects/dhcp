/* memory.c

   Memory-resident database... */

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
"$Id: memory.c,v 1.63 1999/10/07 06:35:42 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct group *clone_group (group, caller)
	struct group *group;
	const char *caller;
{
	struct group *g = new_group (caller);
	if (!g)
		log_fatal ("%s: can't allocate new group", caller);
	*g = *group;
	g -> statements = (struct executable_statement *)0;
	g -> next = group;
	return g;
}

