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

void if_register_socket (info, interface)
	struct interface_info *info;
	struct ifreq *interface;
{
	struct sockaddr_in name;
	int sock;
	struct socklist *tmp;
	int flag;

	name.sin_family = AF_INET;
	name.sin_port = server_port;
	memcpy (&name.sin_addr.s_addr, info -> address.iabuf, 4);
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

	info -> rfdesc = sock;
}

#ifdef USE_SOCKET_SEND
void if_register_send (info, interface)
	struct interface_info *info;
	struct ifreq *interface;
{
	if_register_socket (info, interface);
}

int send_packet (interface, packet, raw, len, to, hto)
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct sockaddr_in *to;
	struct hardware_addr *hto;
{
	return sendto (interface -> wfdesc, raw, len, 0,
		       (struct sockaddr *)to, sizeof *to);
}
#endif /* USE_SOCKET_SEND */

#ifdef USE_SOCKET_RECEIVE
void if_register_send (info, interface)
	struct interface_info *info;
	struct ifreq *interface;
{
/* Do nothing unless we're using a different API for sending packets... */
#ifndef USE_SOCKET_SEND
	if_register_socket (info, interface);
#endif
}
#endif /* USE_SOCKET_RECEIVE */
