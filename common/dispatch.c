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
"@(#) Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <sys/ioctl.h>
#ifdef AF_LINK
#include <net/if_dl.h>
#endif

struct interface_info *interfaces;
static struct hardware_link *interface_links;

/* Use the SIOCGIFCONF ioctl to get a list of all the attached interfaces.
   For each interface that's of type INET and not the loopback interface,
   register that interface with the network I/O software, figure out what
   subnet it's on, and add it to the list of interfaces. */

void discover_interfaces ()
{
	struct interface_info *tmp;
	static char buf [8192];
	struct ifconf ic;
	int i;
	int sock;
	int ifcount = 0;
	int ifix = 0;
	struct hardware_link *lp;
	struct interface_info *iface;

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

	/* Cycle through the list of interfaces looking for IP addresses.
	   Go through twice; once to count the number if addresses, and a
	   second time to copy them into an array of addresses. */
	for (i = 0; i < ic.ifc_len;) {
		struct ifreq *ifp = (struct ifreq *)((caddr_t)ic.ifc_req + i);
#ifdef HAVE_SIN_LEN
		i += (sizeof ifp -> ifr_name) + ifp -> ifr_addr.sa_len;
#else
		i += sizeof *ifp;
#endif

		/* If we have the capability, extract link information
		   and record it in a linked list. */
#ifdef AF_LINK
		if (ifp -> ifr_addr.sa_family == AF_LINK) {
			struct sockaddr_dl *foo = ((struct sockaddr_dl *)
						   (&ifp -> ifr_addr));
			lp = malloc (sizeof *lp);
			if (!lp)
				error ("Can't allocate link pointer.");
			strcpy (lp -> name, ifp -> ifr_name);
			lp -> address.hlen = foo -> sdl_alen;
			lp -> address.htype = foo -> sdl_type;
			memcpy (lp -> address.haddr,
				LLADDR (foo), foo -> sdl_alen);
			lp -> next = interface_links;
			interface_links = lp;
		}
#endif /* AF_LINK */

		if (ifp -> ifr_addr.sa_family == AF_INET) {
			struct sockaddr_in *foo =
				(struct sockaddr_in *)(&ifp -> ifr_addr);
			/* We don't want the loopback interface. */
			if (foo -> sin_addr.s_addr == htonl (INADDR_LOOPBACK))
				continue;
			tmp = ((struct interface_info *)
			       dmalloc (sizeof *tmp, "get_interface_list"));
			if (!tmp)
				error ("Insufficient memory to "
				       "record interface");
			memset (tmp, 0, sizeof *tmp);
			tmp -> address.len = 4;
			memcpy (tmp -> address.iabuf, &foo -> sin_addr.s_addr,
				tmp -> address.len);
			tmp -> local_subnet = find_subnet (tmp -> address);
			strcpy (tmp -> name, ifp -> ifr_name);
			if_register_receive (tmp, ifp);
			if_register_send (tmp, ifp);
			tmp -> next = interfaces;
			interfaces = tmp;
		}
	}

	/* Connect interface link addresses to interfaces. */
	for (lp = interface_links; lp; lp = lp -> next) {
		for (iface = interfaces; iface; iface = iface -> next) {
				if (!strcmp (iface -> name, lp -> name)) {
					note ("%s: %s", lp -> name,
					      print_hw_addr
					      (lp -> address.hlen,
					       lp -> address.htype,
					       lp -> address.haddr));
					iface -> hw_address = lp -> address;
				}
			}
	}
}

/* Wait for packets to come in using select().   When one does, call
   receive_packet to receive the packet and possibly strip hardware
   addressing information from it, and then call do_packet to try to
   do something with it. */

void dispatch ()
{
	struct sockaddr_in from;
	struct hardware hfrom;
	struct iaddr ifrom;
	fd_set r, w, x;
	struct interface_info *l;
	int max = 0;
	int count;
	int result;
	static unsigned char packbuf [4095]; /* Packet input buffer.
						Must be as large as largest
						possible MTU. */

	FD_ZERO (&r);
	FD_ZERO (&w);
	FD_ZERO (&x);

	do {
		/* Set up the read mask. */
		for (l = interfaces; l; l = l -> next) {
			FD_SET (l -> rfdesc, &r);
			FD_SET (l -> rfdesc, &x);
			if (l -> rfdesc > max)
				max = l -> rfdesc;
		}

		/* Wait for a packet or a timeout... XXX */
		count = select (max + 1, &r, &w, &x, (struct timeval *)0);

		/* Get the current time... */
		GET_TIME (&cur_time);

		/* Not likely to be transitory... */
		if (count < 0)
			error ("select: %m");

		for (l = interfaces; l; l = l -> next) {
			if (!FD_ISSET (l -> rfdesc, &r))
				continue;
			if ((result =
			     receive_packet (l, packbuf, sizeof packbuf,
					     &from, &hfrom)) < 0) {
				warn ("receive_packet failed on %s: %m",
				      piaddr (l -> address));
				continue;
			}
			if (result == 0)
				continue;
			note ("request from %s, port %d",
			      inet_ntoa (from.sin_addr),
			      htons (from.sin_port));
			ifrom.len = 4;
			memcpy (ifrom.iabuf, &from.sin_addr, ifrom.len);

			do_packet (l, packbuf, result,
				   from.sin_port, ifrom, &hfrom);
		}
	} while (1);
}

