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

#ifdef USE_BPF

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

struct interface {
	struct in_addr	address;
	int		bpf;
};

static struct interface *if_list;
static int num_ifaces;

#endif

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
#ifdef HAVE_SIN_LEN
		i += (sizeof ifp -> ifr_name) + ifp -> ifr_addr.sa_len;
#else
		i += sizeof *ifp;
#endif
		if (ifp -> ifr_addr.sa_family == AF_INET) {
			struct sockaddr_in *foo =
				(struct sockaddr_in *)(&ifp -> ifr_addr);
			/* We don't want the loopback interface. */
			if (foo -> sin_addr.s_addr == INADDR_LOOPBACK)
				continue;
			if (intbuf) {
				intbuf [ifix] = foo -> sin_addr.s_addr;
#ifdef USE_BPF
				/* Open a bpf device for this interface */
				{
				  int b;
				  char filename[50];

				  for (b = 0; 1; b++)
				  {
				    snprintf(filename, sizeof(filename),
				      "/dev/bpf%d", b);
				    if ((if_list[ifix].bpf =
					open(filename, O_RDWR, 0)) < 0)
				      if (errno == EBUSY)
					continue;
				      else
					error ("Can't find free bpf: %m");
				    else
				      break;
				  }
				  if (ioctl(if_list[ifix].bpf,
				      BIOCSETIF, ifp) < 0)
				    error ("Can't BIOCSETIF on bpf: %m");
				}
				if_list[ifix].address = foo->sin_addr;
#endif
				ifix++;
			} else {
				++ifcount;
			}
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
#ifdef USE_BPF
		num_ifaces = ifcount;
		if (!(if_list = (struct interface *)dmalloc
					(num_ifaces * sizeof(*if_list),
					"get_interface_list")))
			error ("Can't allocate memory for if_list");
#endif
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

#ifndef USE_BPF

int sendpkt (packet, raw, len, to, tolen)
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct sockaddr *to;
	int tolen;
{
	return(sendto(packet->client_sock, raw, len, 0, to, tolen));
}

#else

static void		IpChecksum(struct ip *ip);
static void		UdpChecksum(struct ip *ip);
static u_int32_t	Checksum(u_int16_t *buf, int nwords);

struct raw_packet
{
  u_int16_t space;
  struct ether_header en_hdr;
  struct ip ip;
  struct udphdr udp;
  struct dhcp_packet dhcp;
};

int sendpkt (in_packet, raw, len, to, tolen)
  struct packet *in_packet;
  struct dhcp_packet *raw;
  size_t len;
  struct sockaddr *to;
  int tolen;
{
  int			i, k;
  struct iaddr		dest;
  struct subnet		*subnet;
  struct raw_packet	out_packet;
  struct raw_packet	*const pkt = &out_packet;

/* Find local subnet, or else forward to gateway */

  dest.len = 4;
  memcpy(&dest.iabuf, &((struct sockaddr_in *) to)->sin_addr, dest.len);
  if ((subnet = find_subnet(dest)) == NULL)
    return(sendto(in_packet->client_sock, raw, len, 0, to, tolen));

/* Find interface corresponding to subnet */

  for (i = 0; i < num_ifaces; i++)
  {
    for (k = 0; k < subnet->net.len
      && (dest.iabuf[k] & subnet->netmask.iabuf[k])
	== (subnet->net.iabuf[k] & subnet->netmask.iabuf[k]);
    k++);
    if (k == subnet->net.len)
      break;
  }
  if (i == num_ifaces)
    return(sendto(in_packet->client_sock, raw, len, 0, to, tolen));

/* EtherNet header */

  memset(pkt->en_hdr.ether_dhost, 0xff, sizeof(pkt->en_hdr.ether_dhost));
  memset(pkt->en_hdr.ether_shost, 0x00, sizeof(pkt->en_hdr.ether_shost));
  pkt->en_hdr.ether_type = ETHERTYPE_IP;

/* IP header (except for checksum) */

  pkt->ip.ip_v = 4;
  pkt->ip.ip_hl = 5;
  pkt->ip.ip_tos = IPTOS_LOWDELAY;
  pkt->ip.ip_len = htons(sizeof(pkt->ip) + sizeof(pkt->udp) + len);
  pkt->ip.ip_id = 0;
  pkt->ip.ip_off = 0;
  pkt->ip.ip_ttl = 16;
  pkt->ip.ip_p = IPPROTO_UDP;
  pkt->ip.ip_sum = 0;
  pkt->ip.ip_src = if_list[i].address;
  inet_aton("255.255.255.255", &pkt->ip.ip_dst);

/* UDP header */

  pkt->udp.uh_sport = htons(67);		/* XXX! */
  pkt->udp.uh_dport = in_packet->client_port;
  pkt->udp.uh_ulen = htons(sizeof(pkt->udp) + len);
  pkt->udp.uh_sum = 0;

/* DHCP packet */

  pkt->dhcp = *raw;

/* Compute checksums */

  UdpChecksum(&pkt->ip);
  IpChecksum(&pkt->ip);

/* Fire it off */

  if (write(if_list[i].bpf, &pkt->en_hdr,
      ntohs(pkt->ip.ip_len) + sizeof(pkt->en_hdr)) < 0)
    warn ("Can't deliver packet: write: %m");
  return(0);
}

/*
 * UdpChecksum()
 *
 * Recompute a UDP checksum on a packet
 *
 * UDP pseudo-header (prot = IPPROTO_UDP = 17):
 *
 *  | source IP address	       |
 *  | dest.  IP address	       |
 *  | zero | prot | UDP leng   |
 *
 */

static void
UdpChecksum(struct ip *ip)
{
  struct udphdr	*udp = (struct udphdr *) ((long *) ip + ip->ip_hl);
  u_int32_t	sum;

/* Pad with zero */

  if (ntohs(udp->uh_ulen) & 0x1)
    *((u_char *) udp + ntohs(udp->uh_ulen)) = 0;

/* Do pseudo-header first */

  sum = Checksum((u_int16_t *) &ip->ip_src, 4);
  sum += (u_int16_t) IPPROTO_UDP;
  sum += (u_int16_t) ntohs(udp->uh_ulen);

/* Now do UDP packet itself */

  udp->uh_sum = 0;
  sum += Checksum((u_int16_t *) udp,
	  ((u_int16_t) ntohs(udp->uh_ulen) + 1) >> 1);

/* Flip it & stick it */

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  udp->uh_sum = htons(sum);
}

/*
 * IpChecksum()
 *
 * Recompute an IP header checksum
 *
 */

static void
IpChecksum(struct ip *ip)
{
  u_int32_t	sum;

/* Sum up IP header words */

  ip->ip_sum = 0;
  sum = Checksum((u_int16_t *) ip, ip->ip_hl * 2);

/* Flip it & stick it */

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  ip->ip_sum = htons(sum);
}

/*
 * Checksum()
 *
 * Do the one's complement sum thing over a range of words
 * Ideally, this should get replaced by an assembly version.
 */

static u_int32_t
Checksum(u_int16_t *buf, int nwords)
{
  u_int32_t	sum = 0;

  while (nwords--)
    sum += (u_int16_t) ntohs(*buf++);
  return(sum);
}

#endif

