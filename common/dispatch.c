/* dispatch.c

   Network input dispatcher... */

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
"$Id: dispatch.c,v 1.55 1999/09/08 01:44:21 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct timeout *timeouts;
static struct timeout *free_timeouts;

int interfaces_invalidated;

/* Wait for packets to come in using select().   When one does, call
   receive_packet to receive the packet and possibly strip hardware
   addressing information from it, and then call through the
   bootp_packet_handler hook to try to do something with it. */

void dispatch ()
{
	fd_set r, w, x;
	struct protocol *l;
	int max = 0;
	int count;
	struct timeval tv, *tvp;
	isc_result_t status;

	do {
		/* Call any expired timeouts, and then if there's
		   still a timeout registered, time out the select
		   call then. */
	      another:
		if (timeouts) {
			struct timeout *t;
			if (timeouts -> when <= cur_time) {
				t = timeouts;
				timeouts = timeouts -> next;
				(*(t -> func)) (t -> what);
				t -> next = free_timeouts;
				free_timeouts = t;
				goto another;
			}
			tv.tv_sec = timeouts -> when;
			tv.tv_usec = 0;
			tvp = &tv;
		} else
			tvp = (struct timeval *)0;

		/* Wait for a packet or a timeout... XXX */
		status = omapi_one_dispatch (0, tvp);
	} while (status == ISC_R_TIMEDOUT || status == ISC_R_SUCCESS);
}

int locate_network (packet)
	struct packet *packet;
{
	struct iaddr ia;

	/* If this came through a gateway, find the corresponding subnet... */
	if (packet -> raw -> giaddr.s_addr) {
		struct subnet *subnet;
		ia.len = 4;
		memcpy (ia.iabuf, &packet -> raw -> giaddr, 4);
		subnet = find_subnet (ia);
		if (subnet)
			packet -> shared_network = subnet -> shared_network;
		else
			packet -> shared_network = (struct shared_network *)0;
	} else {
		packet -> shared_network =
			packet -> interface -> shared_network;
	}
	if (packet -> shared_network)
		return 1;
	return 0;
}

void add_timeout (when, where, what)
	TIME when;
	void (*where) PROTO ((void *));
	void *what;
{
	struct timeout *t, *q;

	/* See if this timeout supersedes an existing timeout. */
	t = (struct timeout *)0;
	for (q = timeouts; q; q = q -> next) {
		if (q -> func == where && q -> what == what) {
			if (t)
				t -> next = q -> next;
			else
				timeouts = q -> next;
			break;
		}
		t = q;
	}

	/* If we didn't supersede a timeout, allocate a timeout
	   structure now. */
	if (!q) {
		if (free_timeouts) {
			q = free_timeouts;
			free_timeouts = q -> next;
			q -> func = where;
			q -> what = what;
		} else {
			q = (struct timeout *)malloc (sizeof (struct timeout));
			if (!q)
				log_fatal ("add_timeout: no memory!");
			q -> func = where;
			q -> what = what;
		}
	}

	q -> when = when;

	/* Now sort this timeout into the timeout list. */

	/* Beginning of list? */
	if (!timeouts || timeouts -> when > q -> when) {
		q -> next = timeouts;
		timeouts = q;
		return;
	}

	/* Middle of list? */
	for (t = timeouts; t -> next; t = t -> next) {
		if (t -> next -> when > q -> when) {
			q -> next = t -> next;
			t -> next = q;
			return;
		}
	}

	/* End of list. */
	t -> next = q;
	q -> next = (struct timeout *)0;
}

void cancel_timeout (where, what)
	void (*where) PROTO ((void *));
	void *what;
{
	struct timeout *t, *q;

	/* Look for this timeout on the list, and unlink it if we find it. */
	t = (struct timeout *)0;
	for (q = timeouts; q; q = q -> next) {
		if (q -> func == where && q -> what == what) {
			if (t)
				t -> next = q -> next;
			else
				timeouts = q -> next;
			break;
		}
		t = q;
	}

	/* If we found the timeout, put it on the free list. */
	if (q) {
		q -> next = free_timeouts;
		free_timeouts = q;
	}
}
