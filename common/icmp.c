/* dhcp.c

   ICMP Protocol engine - for sending out pings and receiving
   responses. */

/*
 * Copyright (c) 1997, 1998 The Internet Software Consortium.
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
"$Id: icmp.c,v 1.12 1999/02/24 17:56:45 mellon Exp $ Copyright (c) 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"

static int icmp_protocol_initialized;
static int icmp_protocol_fd;

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

	/* Only initialize icmp once. */
	if (icmp_protocol_initialized)
		log_fatal ("attempted to reinitialize icmp protocol");
	icmp_protocol_initialized = 1;

	/* Get the protocol number (should be 1). */
	proto = getprotobyname ("icmp");
	if (proto)
		protocol = proto -> p_proto;

	/* Get a raw socket for the ICMP protocol. */
	icmp_protocol_fd = socket (AF_INET, SOCK_RAW, protocol);
	if (icmp_protocol_fd < 0)
		log_fatal ("unable to create icmp socket: %m");

	/* Make sure it does routing... */
	state = 0;
	if (setsockopt (icmp_protocol_fd, SOL_SOCKET, SO_DONTROUTE,
			(char *)&state, sizeof state) < 0)
		log_fatal ("Unable to disable SO_DONTROUTE on ICMP socket: %m");

	add_protocol ("icmp", icmp_protocol_fd,
		      icmp_echoreply, (void *)handler);
}

int icmp_echorequest (addr)
	struct iaddr *addr;
{
	struct sockaddr_in to;
	struct icmp icmp;
	int status;

	if (!icmp_protocol_initialized)
		log_fatal ("attempt to use ICMP protocol before initialization.");

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
	status = sendto (icmp_protocol_fd, (char *)&icmp, sizeof icmp, 0,
			 (struct sockaddr *)&to, sizeof to);
	if (status < 0)
		log_error ("icmp_echorequest %s: %m", inet_ntoa(to.sin_addr));

	if (status != sizeof icmp)
		return 0;
	return 1;
}

void icmp_echoreply (protocol)
	struct protocol *protocol;
{
	struct icmp *icfrom;
	struct ip *ip;
	struct sockaddr_in from;
	unsigned char icbuf [1500];
	int status;
	int len, hlen;
	struct iaddr ia;
	void (*handler) PROTO ((struct iaddr, u_int8_t *, int));

	len = sizeof from;
	status = recvfrom (protocol -> fd, (char *)icbuf, sizeof icbuf, 0,
			  (struct sockaddr *)&from, &len);
	if (status < 0) {
		log_error ("icmp_echoreply: %m");
		return;
	}

	/* Find the IP header length... */
	ip = (struct ip *)icbuf;
	hlen = ip -> ip_hl << 2;

	/* Short packet? */
	if (status < hlen + (sizeof *icfrom)) {
		return;
	}

	len = status - hlen;
	icfrom = (struct icmp *)(icbuf + hlen);

	/* Silently discard ICMP packets that aren't echoreplies. */
	if (icfrom -> icmp_type != ICMP_ECHOREPLY) {
		return;
	}

	/* If we were given a second-stage handler, call it. */
	if (protocol -> local) {
		handler = ((void (*) PROTO ((struct iaddr, u_int8_t *, int)))
			   protocol -> local);
		memcpy (ia.iabuf, &from.sin_addr, sizeof from.sin_addr);
		ia.len = sizeof from.sin_addr;

		(*handler) (ia, icbuf, len);
	}
}
