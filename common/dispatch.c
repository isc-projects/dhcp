/* dispatch.c

   Network input dispatcher... */

/*
 * Copyright (c) 1995, 1996, 1998, 1999 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: dispatch.c,v 1.53 1999/02/24 17:56:44 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct protocol *protocols;
struct timeout *timeouts;
static struct timeout *free_timeouts;

int interfaces_invalidated;

#ifdef USE_POLL
/* Wait for packets to come in using poll().  When a packet comes in,
   call receive_packet to receive the packet and possibly strip hardware
   addressing information from it, and then call through the
   bootp_packet_handler hook to try to do something with it. */

void dispatch ()
{
	struct protocol *l;
	int nfds = 0;
	struct pollfd *fds;
	int count;
	int i;
	int to_msec;

	nfds = 0;
	for (l = protocols; l; l = l -> next) {
		++nfds;
	}
	fds = (struct pollfd *)malloc ((nfds) * sizeof (struct pollfd));
	if (!fds)
		log_fatal ("Can't allocate poll structures.");

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
			/* Figure timeout in milliseconds, and check for
			   potential overflow.   We assume that integers
			   are 32 bits, which is harmless if they're 64
			   bits - we'll just get extra timeouts in that
			   case.    Lease times would have to be quite
			   long in order for a 32-bit integer to overflow,
			   anyway. */
			to_msec = timeouts -> when - cur_time;
			if (to_msec > 2147483)
				to_msec = 2147483;
			to_msec *= 1000;
		} else
			to_msec = -1;

		/* Set up the descriptors to be polled. */
		i = 0;
		for (l = protocols; l; l = l -> next) {
			fds [i].fd = l -> fd;
			fds [i].events = POLLIN;
			fds [i].revents = 0;
			++i;
		}

		/* Wait for a packet or a timeout... XXX */
		count = poll (fds, nfds, to_msec);

		/* Get the current time... */
		GET_TIME (&cur_time);

		/* Not likely to be transitory... */
		if (count < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			else
				log_fatal ("poll: %m");
		}

		i = 0;
		for (l = protocols; l; l = l -> next) {
			if ((fds [i].revents & POLLIN)) {
				fds [i].revents = 0;
				if (l -> handler)
					(*(l -> handler)) (l);
				if (interfaces_invalidated)
					break;
			}
			++i;
		}
		interfaces_invalidated = 0;
	} while (1);
}
#else
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

	FD_ZERO (&w);
	FD_ZERO (&x);

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
			tv.tv_sec = timeouts -> when - cur_time;
			tv.tv_usec = 0;
			tvp = &tv;
		} else
			tvp = (struct timeval *)0;

		/* Set up the read mask. */
		FD_ZERO (&r);

		for (l = protocols; l; l = l -> next) {
			FD_SET (l -> fd, &r);
			if (l -> fd > max)
				max = l -> fd;
		}

		/* Wait for a packet or a timeout... XXX */
		count = select (max + 1, &r, &w, &x, tvp);

		/* Get the current time... */
		GET_TIME (&cur_time);

		/* Not likely to be transitory... */
		if (count < 0)
			log_fatal ("select: %m");

		for (l = protocols; l; l = l -> next) {
			if (!FD_ISSET (l -> fd, &r))
				continue;
			if (l -> handler)
				(*(l -> handler)) (l);
			if (interfaces_invalidated)
				break;
		}
		interfaces_invalidated = 0;
	} while (1);
}
#endif /* USE_POLL */

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
				log_fatal ("Can't allocate timeout structure!");
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

/* Add a protocol to the list of protocols... */
struct protocol *add_protocol (name, fd, handler, local)
	char *name;
	int fd;
	void (*handler) PROTO ((struct protocol *));
	void *local;
{
	struct protocol *p;

	p = (struct protocol *)malloc (sizeof *p);
	if (!p)
		log_fatal ("can't allocate protocol struct for %s", name);

	p -> fd = fd;
	p -> handler = handler;
	p -> local = local;

	p -> next = protocols;
	protocols = p;
	return p;
}

void remove_protocol (proto)
	struct protocol *proto;
{
	struct protocol *p, *next, *prev;

	prev = (struct protocol *)0;
	for (p = protocols; p; p = next) {
		next = p -> next;
		if (p == proto) {
			if (prev)
				prev -> next = p -> next;
			else
				protocols = p -> next;
			free (p);
		}
	}
}
