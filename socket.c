/* socket.c

   BSD socket interface code... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
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
"@(#) Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <sys/ioctl.h>

/* List of sockets we're accepting packets on... */
struct socklist {
	struct socklist *next;
	struct sockaddr_in addr;
	int sock;
} *sockets;

/* Return the list of IP addresses associated with each network interface. */

u_int32_t *get_interface_list (count)
	int *count;
{
	u_int32_t *intbuf = (u_int32_t *)0;
	static char buf [8192];
	struct ifconf ic;
	int i;
	int sock;
	int ifcount = 0;
	int ifix = 0;

	/* Create an unbound datagram socket to do the SIOCGIFADDR ioctl on. */
	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		error ("Can't create addrlist socket");

	/* Get the interface configuration information... */
	ic.ifc_len = sizeof buf;
	ic.ifc_ifcu.ifcu_buf = (caddr_t)buf;
	i = ioctl(sock, SIOCGIFCONF, &ic);
	close (sock);
	if (i < 0)
		error ("ioctl: SIOCGIFCONF: %m");

      again:
	/* Cycle through the list of interfaces looking for IP addresses.
	   Go through twice; once to count the number if addresses, and a
	   second time to copy them into an array of addresses. */
	for (i = 0; i < ic.ifc_len;) {
		struct ifreq *ifp = (struct ifreq *)((caddr_t)ic.ifc_req + i);
		i += (sizeof ifp -> ifr_name) + ifp -> ifr_addr.sa_len;
		if (ifp -> ifr_addr.sa_family == AF_INET) {
			struct sockaddr_in *foo =
				(struct sockaddr_in *)(&ifp -> ifr_addr);
			/* We don't want the loopback interface. */
			if (foo -> sin_addr.s_addr == INADDR_LOOPBACK)
				continue;
			if (intbuf)
				intbuf [ifix++] = foo -> sin_addr.s_addr;
			else
				++ifcount;
		}
	}
	/* If we haven't already filled our array, allocate it and go
	   again. */
	if (!intbuf) {
		intbuf = (u_int32_t *)dmalloc ((ifcount + 1)
					       * sizeof (u_int32_t),
					       "get_interface_list");
		if (!intbuf)
			return intbuf;
		goto again;
	}
	*count = ifcount;
	return intbuf;
}

void listen_on (port, address)
	u_int16_t port;
	u_int32_t address;
{
	struct sockaddr_in name;
	int sock;
	struct socklist *tmp;
	int flag;

	name.sin_family = AF_INET;
	name.sin_port = port;
	name.sin_addr.s_addr = address;
	memset (name.sin_zero, 0, sizeof (name.sin_zero));

	/* List addresses on which we're listening. */
	note ("Receiving on %s, port %d",
	      inet_ntoa (name.sin_addr), htons (name.sin_port));
	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		error ("Can't create dhcp socket: %m");

	flag = 1;
	if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR,
			&flag, sizeof flag) < 0)
		error ("Can't set SO_REUSEADDR option on dhcp socket: %m");

	if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST,
			&flag, sizeof flag) < 0)
		error ("Can't set SO_BROADCAST option on dhcp socket: %m");

	if (bind (sock, (struct sockaddr *)&name, sizeof name) < 0)
		error ("Can't bind to dhcp address: %m");

	tmp = (struct socklist *)dmalloc (sizeof (struct socklist),
					  "listen_on");
	if (!tmp)
		error ("Can't allocate memory for socket list.");
	tmp -> addr = name;
	tmp -> sock = sock;
	tmp -> next = sockets;
	sockets = tmp;
}

unsigned char packbuf [4095];	/* Should cover the gnarliest MTU... */

void dispatch ()
{
	struct sockaddr_in from;
	struct iaddr ifrom;
	int fromlen = sizeof from;
	fd_set r, w, x;
	struct socklist *l;
	int max = 0;
	int count;
	int result;

	FD_ZERO (&r);
	FD_ZERO (&w);
	FD_ZERO (&x);

	do {
		/* Set up the read mask. */
		for (l = sockets; l; l = l -> next) {
			FD_SET (l -> sock, &r);
			FD_SET (l -> sock, &x);
			if (l -> sock > max)
				max = l -> sock;
		}

		/* Wait for a packet or a timeout... XXX */
		count = select (max + 1, &r, &w, &x, (struct timeval *)0);

		/* Get the current time... */
		GET_TIME (&cur_time);

		/* Not likely to be transitory... */
		if (count < 0)
			error ("select: %m");

		for (l = sockets; l; l = l -> next) {
			if (!FD_ISSET (l -> sock, &r))
				continue;
			if ((result =
			     recvfrom (l -> sock, packbuf, sizeof packbuf, 0,
				       (struct sockaddr *)&from, &fromlen))
			    < 0) {
				warn ("recvfrom failed on %s: %m",
				      inet_ntoa (l -> addr.sin_addr));
				sleep (5);
				continue;
			}
			note ("request from %s, port %d",
			      inet_ntoa (from.sin_addr),
			      htons (from.sin_port));
			ifrom.len = 4;
			memcpy (ifrom.iabuf, &from.sin_addr, ifrom.len);

			do_packet (packbuf, result, from.sin_port,
				   ifrom, l -> sock);
		}
	} while (1);
}

