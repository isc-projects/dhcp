/* auth.c

   Subroutines having to do with authentication. */

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
static char ocopyright[] =
"$Id: auth.c,v 1.2 1999/03/16 05:50:31 mellon Exp $ Copyright 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.";
#endif

#include "dhcpd.h"

static struct hash_table *auth_key_hash;

void enter_auth_key (key_id, key)
	struct data_string *key_id;
	struct auth_key *key;
{
	if (!auth_key_hash)
		auth_key_hash = new_hash ();
	if (!auth_key_hash)
		log_fatal ("Can't allocate authentication key hash.");
	add_hash (auth_key_hash, key_id -> data, key_id -> len,
		  (unsigned char *)key);
}

struct auth_key *auth_key_lookup (key_id)
	struct data_string *key_id;
{
	return (struct auth_key *)hash_lookup (auth_key_hash,
					       key_id -> data, key_id -> len);
}

