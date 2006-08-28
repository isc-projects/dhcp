/* socket.c

   BSD socket interface code... */

/*
 * Copyright (c) 2004-2006 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 *
 * This software has been written for Internet Systems Consortium
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about Internet Systems Consortium, see
 * ``http://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

/* SO_BINDTODEVICE support added by Elliot Poger (poger@leland.stanford.edu).
 * This sockopt allows a socket to be bound to a particular interface,
 * thus enabling the use of DHCPD on a multihomed host.
 * If SO_BINDTODEVICE is defined in your system header files, the use of
 * this sockopt will be automatically enabled. 
 * I have implemented it under Linux; other systems should be doable also.
 */

#ifndef lint
static char copyright[] =
"$Id: socket.c,v 1.58.116.2 2006/08/28 18:16:49 shane Exp $ Copyright (c) 2004 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#ifdef USE_SOCKET_FALLBACK
# if !defined (USE_SOCKET_SEND)
#  define if_register_send if_register_fallback
#  define send_packet send_fallback
#  define if_reinitialize_send if_reinitialize_fallback
# endif
#endif

static int once = 0;

/* Reinitializes the specified interface after an address change.   This
   is not required for packet-filter APIs. */

#if defined (USE_SOCKET_SEND) || defined (USE_SOCKET_FALLBACK)
void if_reinitialize_send (info)
	struct interface_info *info;
{
#if 0
#ifndef USE_SOCKET_RECEIVE
	once = 0;
	close (info -> wfdesc);
#endif
	if_register_send (info);
#endif
}
#endif

#ifdef USE_SOCKET_RECEIVE
void if_reinitialize_receive (info)
	struct interface_info *info;
{
#if 0
	once = 0;
	close (info -> rfdesc);
	if_register_receive (info);
#endif
}
#endif

#if defined (USE_SOCKET_SEND) || \
	defined (USE_SOCKET_RECEIVE) || \
		defined (USE_SOCKET_FALLBACK)
/* Generic interface registration routine... */
int
if_register_socket(struct interface_info *info, int family, int do_multicast) {
	struct sockaddr_storage name;
	int name_len;
	int sock;
	int flag;
	int domain;

	/* INSIST((family == AF_INET) || (family == AF_INET6)); */

#if !defined (HAVE_SO_BINDTODEVICE) && !defined (USE_FALLBACK)
	/* Make sure only one interface is registered. */
	if (once) {
		log_fatal ("The standard socket API can only support %s",
		       "hosts with a single network interface.");
	}
	once = 1;
#endif

	/* 
	 * Set up the address we're going to bind to, depending on the
	 * address family. 
	 */ 
	memset(&name, 0, sizeof(name));
	if (family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&name; 
		addr->sin_family = AF_INET;
		addr->sin_port = local_port;
		memcpy(&addr->sin_addr,
		       &local_address,
		       sizeof(addr->sin_addr));
		name_len = sizeof(*addr);
		domain = PF_INET;
	} else { 
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&name; 
		addr->sin6_family = AF_INET6;
		addr->sin6_port = local_port;
		memcpy(&addr->sin6_addr,
		       &local_address6, 
		       sizeof(addr->sin6_addr));
		name_len = sizeof(*addr);
		domain = PF_INET6;
	}

	/* Make a socket... */
	sock = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		log_fatal("Can't create dhcp socket: %m");
	}

	/* Set the REUSEADDR option so that we don't fail to start if
	   we're being restarted. */
	flag = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&flag, sizeof(flag)) < 0) {
		log_fatal("Can't set SO_REUSEADDR option on dhcp socket: %m");
	}

	/* Set the BROADCAST option so that we can broadcast DHCP responses.
	   We shouldn't do this for fallback devices, and we can detect that
	   a device is a fallback because it has no ifp structure. */
	if (info->ifp &&
	    (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
			 (char *)&flag, sizeof(flag)) < 0)) {
		log_fatal("Can't set SO_BROADCAST option on dhcp socket: %m");
	}

	/* Bind the socket to this interface's IP address. */
	if (bind(sock, (struct sockaddr *)&name, name_len) < 0) {
		log_error("Can't bind to dhcp address: %m");
		log_error("Please make sure there is no other dhcp server");
		log_error("running and that there's no entry for dhcp or");
		log_error("bootp in /etc/inetd.conf.   Also make sure you");
		log_error("are not running HP JetAdmin software, which");
		log_fatal("includes a bootp server.");
	}

#if defined (HAVE_SO_BINDTODEVICE)
	/* Bind this socket to this interface. */
	if (info->ifp &&
	    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			(char *)(info -> ifp), sizeof(*(info -> ifp))) < 0) {
		log_fatal("setsockopt: SO_BINDTODEVICE: %m");
	}
#endif
	
	if ((family == AF_INET6) && do_multicast) {
		struct ipv6_mreq mreq;

		/*
		 * Join the DHCPv6 multicast groups so we will receive
		 * multicast messages.
		 */
		if (inet_pton(AF_INET6, All_DHCP_Relay_Agents_and_Servers,
			      &mreq.ipv6mr_multiaddr) <= 0) {
			log_fatal("inet_pton: unable to convert '%s'", 
				  All_DHCP_Relay_Agents_and_Servers);
		}
		mreq.ipv6mr_interface = 0;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, 
			       &mreq, sizeof(mreq)) < 0) {
			log_fatal("setsockopt: IPV6_ADD_MEMBERSHIP: %m");
		}
		if (inet_pton(AF_INET6, All_DHCP_Servers,
			      &mreq.ipv6mr_multiaddr) <= 0) {
			log_fatal("inet_pton: unable to convert '%s'", 
				  All_DHCP_Servers);
		}
		mreq.ipv6mr_interface = 0;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, 
			       &mreq, sizeof(mreq)) < 0) {
			log_fatal("setsockopt: IPV6_ADD_MEMBERSHIP: %m");
		}
	}

	/* IP_BROADCAST_IF instructs the kernel which interface to send
	 * IP packets whose destination address is 255.255.255.255.  These
	 * will be treated as subnet broadcasts on the interface identified
	 * by ip address (info -> primary_address).  This is only known to
	 * be defined in SCO system headers, and may not be defined in all
	 * releases.
	 */
#if defined(SCO) && defined(IP_BROADCAST_IF)
        if (setsockopt (sock, IPPROTO_IP, IP_BROADCAST_IF,
                        &info -> primary_address,
                        sizeof (info -> primary_address)) < 0)
                log_fatal ("Can't set IP_BROADCAST_IF on dhcp socket: %m");
#endif

	return sock;
}
#endif /* USE_SOCKET_SEND || USE_SOCKET_RECEIVE || USE_SOCKET_FALLBACK */

#if defined (USE_SOCKET_SEND) || defined (USE_SOCKET_FALLBACK)
void if_register_send (info)
	struct interface_info *info;
{
#ifndef USE_SOCKET_RECEIVE
	info -> wfdesc = if_register_socket (info, AF_INET, 0);
#if defined (USE_SOCKET_FALLBACK)
	/* Fallback only registers for send, but may need to receive as
	   well. */
	info -> rfdesc = info -> wfdesc;
#endif
#else
	info -> wfdesc = info -> rfdesc;
#endif
	if (!quiet_interface_discovery)
		log_info ("Sending on   Socket/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}

#if defined (USE_SOCKET_SEND)
void if_deregister_send (info)
	struct interface_info *info;
{
#ifndef USE_SOCKET_RECEIVE
	close (info -> wfdesc);
#endif
	info -> wfdesc = -1;

	if (!quiet_interface_discovery)
		log_info ("Disabling output on Socket/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}
#endif /* USE_SOCKET_SEND */
#endif /* USE_SOCKET_SEND || USE_SOCKET_FALLBACK */

#ifdef USE_SOCKET_RECEIVE
void if_register_receive (info)
	struct interface_info *info;
{
	/* If we're using the socket API for sending and receiving,
	   we don't need to register this interface twice. */
	info -> rfdesc = if_register_socket (info, AF_INET, 0);
	if (!quiet_interface_discovery)
		log_info ("Listening on Socket/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}

void if_deregister_receive (info)
	struct interface_info *info;
{
	close (info -> rfdesc);
	info -> rfdesc = -1;

	if (!quiet_interface_discovery)
		log_info ("Disabling input on Socket/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}
#endif /* USE_SOCKET_RECEIVE */


void
if_register6(struct interface_info *info, int do_multicast) {
	info->rfdesc = if_register_socket(info, AF_INET6, do_multicast);
	info->wfdesc = info->rfdesc;
	if (!quiet_interface_discovery) {
		if (info->shared_network != NULL) {
			log_info("Listening on Socket/%s/%s", info->name, 
				 info->shared_network->name);
			log_info("Sending on   Socket/%s/%s", info->name,
				 info->shared_network->name);
		} else {
			log_info("Listening on Socket/%s", info->name);
			log_info("Sending on   Socket/%s", info->name);
		}
	}
}

void 
if_deregister6(struct interface_info *info) {
	/* 
	 * XXX: it would be nice to check for >= 0, but we need to change 
	 *      interface_allocate() to set the file descriptors for that.
	 */
	close(info->rfdesc);	
	info->rfdesc = -1;
	close(info->wfdesc);	
	info->wfdesc = -1;

	if (!quiet_interface_discovery) {
		if (info->shared_network != NULL) {
			log_info("Disabling input on  Socket/%s/%s", info->name,
		       		 info->shared_network->name);
			log_info("Disabling output on Socket/%s/%s", info->name,
		       		 info->shared_network->name);
		} else {
			log_info("Disabling input on  Socket/%s", info->name);
			log_info("Disabling output on Socket/%s", info->name);
		}
	}
}

#if defined (USE_SOCKET_SEND) || defined (USE_SOCKET_FALLBACK)
ssize_t send_packet (interface, packet, raw, len, from, to, hto)
	struct interface_info *interface;
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct in_addr from;
	struct sockaddr_in *to;
	struct hardware *hto;
{
	int result;
#ifdef IGNORE_HOSTUNREACH
	int retry = 0;
	do {
#endif
		result = sendto (interface -> wfdesc, (char *)raw, len, 0,
				 (struct sockaddr *)to, sizeof *to);
#ifdef IGNORE_HOSTUNREACH
	} while (to -> sin_addr.s_addr == htonl (INADDR_BROADCAST) &&
		 result < 0 &&
		 (errno == EHOSTUNREACH ||
		  errno == ECONNREFUSED) &&
		 retry++ < 10);
#endif
	if (result < 0) {
		log_error ("send_packet: %m");
		if (errno == ENETUNREACH)
			log_error ("send_packet: please consult README file%s",
				   " regarding broadcast address.");
	}
	return result;
}

#endif /* USE_SOCKET_SEND || USE_SOCKET_FALLBACK */

ssize_t send_packet6(struct interface_info *interface,
		     struct packet *packet,
		     struct dhcp_packet *raw, 
		     size_t len, 
		     struct in6_addr from, 
		     struct sockaddr_in6 *to, 
		     struct hardware *hto) {
	int result;

	result = sendto(interface->wfdesc, (char *)raw, len, 0,
		        (struct sockaddr *)to, sizeof(*to));
	if (result < 0) {
		log_error("send_packet6: %m");
	}
	return result;
}

#ifdef USE_SOCKET_RECEIVE
ssize_t receive_packet (interface, buf, len, from, hfrom)
	struct interface_info *interface;
	unsigned char *buf;
	size_t len;
	struct sockaddr_in *from;
	struct hardware *hfrom;
{
	SOCKLEN_T flen = sizeof *from;
	int result;

	/*
	 * The normal Berkeley socket interface doesn't give us any way
	 * to know what hardware interface we received the message on,
	 * but we should at least make sure the structure is emptied.
	 */
	memset(hfrom, 0, sizeof(*hfrom));

#ifdef IGNORE_HOSTUNREACH
	int retry = 0;
	do {
#endif
		result = recvfrom (interface -> rfdesc, (char *)buf, len, 0,
				   (struct sockaddr *)from, &flen);
#ifdef IGNORE_HOSTUNREACH
	} while (result < 0 &&
		 (errno == EHOSTUNREACH ||
		  errno == ECONNREFUSED) &&
		 retry++ < 10);
#endif
	return result;
}

#endif /* USE_SOCKET_RECEIVE */

ssize_t 
receive_packet6(struct interface_info *interface, unsigned char *buf,
		size_t len, struct sockaddr_in6 *from) {
	SOCKLEN_T flen = sizeof(*from);
	int result;

	result = recvfrom(interface->rfdesc, (char *)buf, len, 0,
			  (struct sockaddr *)from, &flen);
	return result;
}

#if defined (USE_SOCKET_FALLBACK)
/* This just reads in a packet and silently discards it. */

isc_result_t fallback_discard (object)
	omapi_object_t *object;
{
	char buf [1540];
	struct sockaddr_in from;
	SOCKLEN_T flen = sizeof from;
	int status;
	struct interface_info *interface;

	if (object -> type != dhcp_type_interface)
		return ISC_R_INVALIDARG;
	interface = (struct interface_info *)object;

	status = recvfrom (interface -> wfdesc, buf, sizeof buf, 0,
			   (struct sockaddr *)&from, &flen);
#if defined (DEBUG)
	/* Only report fallback discard errors if we're debugging. */
	if (status < 0) {
		log_error ("fallback_discard: %m");
		return ISC_R_UNEXPECTED;
	}
#endif
	return ISC_R_SUCCESS;
}
#endif /* USE_SOCKET_FALLBACK */

#if defined (USE_SOCKET_SEND)
int can_unicast_without_arp (ip)
	struct interface_info *ip;
{
	return 0;
}

int can_receive_unicast_unconfigured (ip)
	struct interface_info *ip;
{
#if defined (SOCKET_CAN_RECEIVE_UNICAST_UNCONFIGURED)
	return 1;
#else
	return 0;
#endif
}

int supports_multiple_interfaces (ip)
	struct interface_info *ip;
{
#if defined (SO_BINDTODEVICE)
	return 1;
#else
	return 0;
#endif
}

/* If we have SO_BINDTODEVICE, set up a fallback interface; otherwise,
   do not. */

void maybe_setup_fallback ()
{
#if defined (USE_SOCKET_FALLBACK)
	isc_result_t status;
	struct interface_info *fbi = (struct interface_info *)0;
	if (setup_fallback (&fbi, MDL)) {
		fbi -> wfdesc = if_register_socket (fbi, AF_INET, 0);
		fbi -> rfdesc = fbi -> wfdesc;
		log_info ("Sending on   Socket/%s%s%s",
		      fbi -> name,
		      (fbi -> shared_network ? "/" : ""),
		      (fbi -> shared_network ?
		       fbi -> shared_network -> name : ""));
	
		status = omapi_register_io_object ((omapi_object_t *)fbi,
						   if_readsocket, 0,
						   fallback_discard, 0, 0);
		if (status != ISC_R_SUCCESS)
			log_fatal ("Can't register I/O handle for %s: %s",
				   fbi -> name, isc_result_totext (status));
		interface_dereference (&fbi, MDL);
	}
#endif
}
#endif /* USE_SOCKET_SEND */
