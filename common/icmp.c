/* dhcp.c

   ICMP Protocol engine - for sending out pings and receiving
   responses. */

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
"$Id: icmp.c,v 1.16 2000/01/05 18:01:41 mellon Exp $ Copyright (c) 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"

struct icmp_state {
	OMAPI_OBJECT_PREAMBLE;
	int socket;
	void (*icmp_handler) PROTO ((struct iaddr, u_int8_t *, int));
};

static struct icmp_state *icmp_state;
static omapi_object_type_t *dhcp_type_icmp;

/* Initialize the ICMP protocol. */

void icmp_startup (routep, handler)
	int routep;
	void (*handler) PROTO ((struct iaddr, u_int8_t *, int));
{
	struct protoent *proto;
	int protocol = 1;
	struct sockaddr_in from;
	int fd;
	int state;
	struct icmp_state *new;
	omapi_object_t *h;
	isc_result_t result;

	/* Only initialize icmp once. */
	if (dhcp_type_icmp)
		log_fatal ("attempted to reinitialize icmp protocol");

	result = omapi_object_type_register (&dhcp_type_icmp,
					     "icmp", 0, 0, 0, 0, 0, 0, 0, 0);

	if (result != ISC_R_SUCCESS)
		log_fatal ("Can't register icmp object type: %s",
			   isc_result_totext (result));

	new = (struct icmp_state *)dmalloc (sizeof *new, "icmp_startup");
	if (!new)
		log_fatal ("Unable to allocate state for icmp protocol");
	memset (new, 0, sizeof *new);
	new -> refcnt = 1;
	new -> type = dhcp_type_icmp;
	new -> icmp_handler = handler;

	/* Get the protocol number (should be 1). */
	proto = getprotobyname ("icmp");
	if (proto)
		protocol = proto -> p_proto;

	/* Get a raw socket for the ICMP protocol. */
	new -> socket = socket (AF_INET, SOCK_RAW, protocol);
	if (new -> socket < 0)
		log_fatal ("unable to create icmp socket: %m");

#if defined (HAVE_SETFD)
	if (fcntl (new -> socket, F_SETFD, 1) < 0)
		log_error ("Can't set close-on-exec on icmp socket: %m");
#endif

	/* Make sure it does routing... */
	state = 0;
	if (setsockopt (new -> socket, SOL_SOCKET, SO_DONTROUTE,
			(char *)&state, sizeof state) < 0)
		log_fatal ("Can't disable SO_DONTROUTE on ICMP socket: %m");

	result = omapi_register_io_object ((omapi_object_t *)new,
					   icmp_readsocket, 0,
					   icmp_echoreply, 0, 0);
	if (result != ISC_R_SUCCESS)
		log_fatal ("Can't register icmp handle: %s",
			   isc_result_totext (result));
	icmp_state = new;
}

int icmp_readsocket (h)
	omapi_object_t *h;
{
	struct icmp_state *state;

	state = (struct icmp_state *)h;
	return state -> socket;
}

int icmp_echorequest (addr)
	struct iaddr *addr;
{
	struct sockaddr_in to;
	struct icmp icmp;
	int status;

	if (!icmp_state)
		log_fatal ("ICMP protocol used before initialization.");

#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	to.sin_family = AF_INET;
	to.sin_port = 0; /* unused. */
	memcpy (&to.sin_addr, addr -> iabuf, sizeof to.sin_addr); /* XXX */

	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_cksum = 0;
	icmp.icmp_seq = 0;
#ifdef PTRSIZE_64BIT
	icmp.icmp_id = (((u_int32_t)(u_int64_t)addr) ^
  			(u_int32_t)(((u_int64_t)addr) >> 32));
#else
	icmp.icmp_id = (u_int32_t)addr;
#endif
	memset (&icmp.icmp_dun, 0, sizeof icmp.icmp_dun);

	icmp.icmp_cksum = wrapsum (checksum ((unsigned char *)&icmp,
					     sizeof icmp, 0));

	/* Send the ICMP packet... */
	status = sendto (icmp_state -> socket, (char *)&icmp, sizeof icmp, 0,
			 (struct sockaddr *)&to, sizeof to);
	if (status < 0)
		log_error ("icmp_echorequest %s: %m", inet_ntoa(to.sin_addr));

	if (status != sizeof icmp)
		return 0;
	return 1;
}

isc_result_t icmp_echoreply (h)
	omapi_object_t *h;
{
	struct icmp *icfrom;
	struct ip *ip;
	struct sockaddr_in from;
	unsigned char icbuf [1500];
	int status;
	int len, hlen;
	struct iaddr ia;
	struct icmp_state *state;

	state = (struct icmp_state *)h;

	len = sizeof from;
	status = recvfrom (state -> socket, (char *)icbuf, sizeof icbuf, 0,
			  (struct sockaddr *)&from, &len);
	if (status < 0) {
		log_error ("icmp_echoreply: %m");
		return ISC_R_UNEXPECTED;
	}

	/* Find the IP header length... */
	ip = (struct ip *)icbuf;
	hlen = ip -> ip_hl << 2;

	/* Short packet? */
	if (status < hlen + (sizeof *icfrom)) {
		return ISC_R_SUCCESS;
	}

	len = status - hlen;
	icfrom = (struct icmp *)(icbuf + hlen);

	/* Silently discard ICMP packets that aren't echoreplies. */
	if (icfrom -> icmp_type != ICMP_ECHOREPLY) {
		return ISC_R_SUCCESS;
	}

	/* If we were given a second-stage handler, call it. */
	if (state -> icmp_handler) {
		memcpy (ia.iabuf, &from.sin_addr, sizeof from.sin_addr);
		ia.len = sizeof from.sin_addr;

		(*state -> icmp_handler) (ia, icbuf, len);
	}
	return ISC_R_SUCCESS;
}
