/* hash.h

   Definitions for hashing... */

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

#define DEFAULT_HASH_SIZE	97

typedef int (*hash_reference) (void *, void *, const char *, int);
typedef int (*hash_dereference) (void *, const char *, int);

struct hash_bucket {
	struct hash_bucket *next;
	const unsigned char *name;
	unsigned len;
	void *value;
};

struct hash_table {
	unsigned hash_count;
	struct hash_bucket *buckets [DEFAULT_HASH_SIZE];
	hash_reference referencer;
	hash_dereference dereferencer;
};

struct named_hash {
	struct named_hash *next;
	const char *name;
	struct hash_table *hash;
};
