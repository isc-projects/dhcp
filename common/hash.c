/* hash.c

   Routines for manipulating hash tables... */

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
"$Id: hash.c,v 1.14 1999/04/12 21:33:34 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static INLINE int do_hash PROTO ((unsigned char *, int, int));

struct hash_table *new_hash ()
{
	struct hash_table *rv = new_hash_table (DEFAULT_HASH_SIZE, "new_hash");
	if (!rv)
		return rv;
	memset (&rv -> buckets [0], 0,
		DEFAULT_HASH_SIZE * sizeof (struct hash_bucket *));
	return rv;
}

static INLINE int do_hash (name, len, size)
	unsigned char *name;
	int len;
	int size;
{
	register int accum = 0;
	register unsigned char *s = (unsigned char *)name;
	int i = len;
	while (i--) {
		/* Add the character in... */
		accum += *s++;
		/* Add carry back in... */
		while (accum > 255) {
			accum = (accum & 255) + (accum >> 8);
		}
	}
	return accum % size;
}

void add_hash (table, name, len, pointer)
	struct hash_table *table;
	int len;
	unsigned char *name;
	unsigned char *pointer;
{
	int hashno;
	struct hash_bucket *bp;

	if (!table)
		return;

	if (!len)
		len = strlen ((char *)name);

	hashno = do_hash (name, len, table -> hash_count);
	bp = new_hash_bucket ("add_hash");

	if (!bp) {
		log_error ("Can't add %s to hash table.", name);
		return;
	}
	bp -> name = name;
	bp -> value = pointer;
	bp -> next = table -> buckets [hashno];
	bp -> len = len;
	table -> buckets [hashno] = bp;
}

void delete_hash_entry (table, name, len)
	struct hash_table *table;
	int len;
	unsigned char *name;
{
	int hashno;
	struct hash_bucket *bp, *pbp = (struct hash_bucket *)0;

	if (!table)
		return;

	if (!len)
		len = strlen ((char *)name);

	hashno = do_hash (name, len, table -> hash_count);

	/* Go through the list looking for an entry that matches;
	   if we find it, delete it. */
	for (bp = table -> buckets [hashno]; bp; bp = bp -> next) {
		if ((!bp -> len &&
		     !strcmp ((char *)bp -> name, (char *)name)) ||
		    (bp -> len == len &&
		     !memcmp (bp -> name, name, len))) {
			if (pbp) {
				pbp -> next = bp -> next;
			} else {
				table -> buckets [hashno] = bp -> next;
			}
			free_hash_bucket (bp, "delete_hash_entry");
			break;
		}
		pbp = bp;	/* jwg, 9/6/96 - nice catch! */
	}
}

unsigned char *hash_lookup (table, name, len)
	struct hash_table *table;
	unsigned char *name;
	int len;
{
	int hashno;
	struct hash_bucket *bp;

	if (!table)
		return (unsigned char *)0;
	if (!len)
		len = strlen ((char *)name);

	hashno = do_hash (name, len, table -> hash_count);

	for (bp = table -> buckets [hashno]; bp; bp = bp -> next) {
		if (len == bp -> len
		    && !memcmp (bp -> name, name, len))
			return bp -> value;
	}
	return (unsigned char *)0;
}

