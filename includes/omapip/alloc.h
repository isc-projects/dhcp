/* alloc.h

   Definitions for the object management API protocol memory allocation... */

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

isc_result_t omapi_buffer_new (omapi_buffer_t **, const char *, int);
isc_result_t omapi_buffer_reference (omapi_buffer_t **,
				     omapi_buffer_t *, const char *, int);
isc_result_t omapi_buffer_dereference (omapi_buffer_t **, const char *, int);

#if defined (DEBUG_MEMORY_LEAKAGE) || defined (DEBUG_MALLOC_POOL)
#define DMDOFFSET (sizeof (struct dmalloc_preamble))
#define DMLFSIZE 16
#define DMUFSIZE 16
#define DMDSIZE (DMDOFFSET + DMLFSIZE + DMUFSIZE)

struct dmalloc_preamble {
	struct dmalloc_preamble *prev, *next;
	const char *file;
	int line;
	size_t size;
	unsigned long generation;
	unsigned char low_fence [DMLFSIZE];
};
#else
#define DMDOFFSET 0
#define DMDSIZE 0
#endif

#if defined (DEBUG_RC_HISTORY)
#if !defined (RC_HISTORY_MAX)
# define RC_HISTORY_MAX 256
#endif

struct rc_history_entry {
	const char *file;
	int line;
	VOIDPTR addr;
	int refcnt;
};

#define rc_register(x, l, y, z) do { \
	rc_history [rc_history_index].file = (x); \
	rc_history [rc_history_index].line = (l); \
	rc_history [rc_history_index].addr = (y); \
	rc_history [rc_history_index].refcnt = (z); \
	if (++rc_history_index == RC_HISTORY_MAX) \
		rc_history_index = 0;\
	} while (0)
#define rc_register_mdl(y, z) \
	rc_register (__FILE__, __LINE__, y, z)
#else
#define rc_register(file, line, addr, refcnt)
#define rc_register_mdl(addr, refcnt)
#endif

#if defined (DEBUG_MEMORY_LEAKAGE) || defined (DEBUG_MALLOC_POOL)
extern struct dmalloc_preamble *dmalloc_list;
extern unsigned long dmalloc_outstanding;
extern unsigned long dmalloc_longterm;
extern unsigned long dmalloc_generation;
extern unsigned long dmalloc_cutoff_generation;
#endif

#if defined (DEBUG_RC_HISTORY)
extern struct rc_history_entry rc_history [RC_HISTORY_MAX];
extern int rc_history_index;
#endif
