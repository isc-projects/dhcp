/* dns.c

   Domain Name Service subroutine. */

/*
 * Copyright (C) 1992 by Ted Lemon.
 * Copyright (c) 1997 The Internet Software Consortium.
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
 * This file is based on software written in 1992 by Ted Lemon for
 * a portable network boot loader.   That original code base has been
 * substantially modified for use in the Internet Software Consortium
 * DHCP suite.
 *
 * These later modifications were done on behalf of the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: dns.c,v 1.1 1997/03/08 02:24:16 mellon Exp $ Copyright (c) 1997 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "arpa/nameser.h"

/* Initialize the DNS protocol. */

void dns_startup (handler)
	void (*handler) PROTO ((struct iaddr, u_int8_t *, int));
{
	struct protoent *proto;
	int protocol = 1;
	struct sockaddr_in from;
	int fd;

	/* Only initialize icmp once. */
	if (icmp_protocol_initialized)
		error ("attempted to reinitialize icmp protocol");
	icmp_protocol_initialized = 1;

	/* Get the protocol number (should be 1). */
	proto = getprotobyname ("icmp");
	if (proto)
		protocol = proto -> p_proto;

	/* Get a raw socket for the ICMP protocol. */
	icmp_protocol_fd = socket (AF_INET, SOCK_RAW, protocol);
	if (!icmp_protocol_fd)
		error ("unable to create icmp socket: %m");

	if (setsockopt (icmp_protocol_fd, SOL_SOCKET, SO_DONTROUTE,
			(char *)&routep, sizeof routep))
		error ("Can't set SO_DONTROUTE on ICMP socket: %m");

	add_protocol ("icmp", icmp_protocol_fd, icmp_echoreply, handler);
}

/* Label manipulation stuff; see RFC1035, page 28 section 4.1.2 and
   page 30, section 4.1.4. */

/* addlabel copies a label into the specified buffer, putting the length of
   the label in the first character, the contents of the label in subsequent
   characters, and returning the length of the conglomeration. */

addlabel (buf, label)
     unsigned char *buf;
     unsigned char *label;
{
  *buf = strlen (label);
  strcpy (buf + 1, label);
  return *buf + 1;
}

/* skipname skips over all of the labels in a single domain name,
   returning the length of the domain name. */

skipname (label)
     unsigned char *label;
{
  if (*label & INDIR_MASK)
    return 2;
  if (*label == 0)
    return 1;
  return *label + 1 + skipname (label + *label + 1);
}

/* copy_out_name copies out the name appearing at the specified location
   into a string, stored as fields seperated by dots rather than lengths
   and labels.   The length of the label-formatted name is returned. */

copy_out_name (base, name, buf)
     unsigned char *base;
     unsigned char *name;
     unsigned char *buf;
{
  if (*name & INDIR_MASK)
    {
      int offset = (*name & ~INDIR_MASK) + (*name + 1);
      return copy_out_name (base, base + offset, buf);
    }
  if (!*name)
    {
      *buf = 0;
      return 1;
    }
  memcpy (buf, name + 1, *name);
  *(buf + *name) = '.';
  return *name + 1 + copy_out_name (base, name + *name + 1, buf + *name + 1);
}

/* ns_inaddr_lookup constructs a PTR lookup query for an internet address -
   e.g., 1.200.9.192.in-addr.arpa.   If the specified timeout period passes
   before the query is satisfied, or if the query fails, the callback is
   called with a null pointer.   Otherwise, the callback is called with the
   address of the string returned by the name server. */

ns_inaddr_lookup (inaddr, timeout, callback)
     Address *inaddr;
     int timeout;
     void (*callback) (char *);
{
  unsigned char namebuf [MAXDNAME];
  unsigned char *s = namebuf;
  unsigned char *label;
  int i;
  unsigned char c;

  for (i = 3; i >= 0; --i)
    {
      label = s++;
      *label = 1;
      c = inaddr -> addr [i];
      if (c > 100)
	{
	  ++*label;
	  *s++ = '0' + c / 100;
	}
      if (c > 10)
	{
	  ++*label;
	  *s++ = '0' + ((c / 10) % 10);
	}
      *s++ = '0' + (c % 10);
    }
  s += addlabel (s, "in-addr");
  s += addlabel (s, "arpa");
  *s = 0;
  nslookup (namebuf, T_PTR, C_IN, timeout, callback);
}

nslookup (qname, qtype, qclass, timeout, callback)
     char *qname;
     int qtype;
     int qclass;
     int timeout;
     void (*callback) (char *);
{
  HEADER hdr;
  unsigned char buf [MTUSIZE];
  unsigned char query [PACKETSZ];
  unsigned char *s;
  int len;
  void ns_timeout ();
  int i;

	/* Construct a query ID... */
  do
    ns_query_id = random ();
  while (ns_query_id < 2048);

  memset (&hdr, 0, sizeof hdr);
  hdr.id = ns_query_id;
  hdr.rd = 1;
  hdr.opcode = QUERY;
  hdr.qdcount = 1;
  nsswap (&hdr);

  memcpy (query, &hdr, sizeof hdr);
  len = sizeof hdr;

  strcpy (&query [len], qname);
  len += strlen (qname) + 1;

  s = &query [len];
  PUTSHORT (qtype, s);
  len += sizeof (short);
  PUTSHORT (qclass, s);
  len += sizeof (short);
	/* Tack on an extra zero for the checksummer... */
  *s++ = 0;

	/* Create the packet header... */
  len = build_udp_packet (buf, sizeof buf, query, len,
			  ns_query_id, NAMESERVER_PORT,
			  &myiaddr, &nsiaddr);

	/* Save the callback vector... */
  ns_callback = callback;

	/* Push a packet out, retrying in an exponential decay starting
	   with one second, and time out when the user specifies... */
  pushpacket (buf, len, (void (*) (char *, int))0, ns_timeout, timeout, 1);
}

void ns_timeout ()
{
  void (*callback) (char *) = ns_callback;
  ns_callback = (void (*) (char *))0;
  ns_query_id = 0;
  (*callback) ((char *)0);
}

ns_packet (ns_header, udp, ip, machine_header)
     HEADER *ns_header;
     struct udphdr *udp;
     struct ip *ip;
     unsigned char *machine_header;
{
  unsigned char *base = (unsigned char *)(ns_header + 1);
  unsigned char *dptr;
  void (*callback) (char *) = ns_callback;
  int type;
  int class;
  int ttl;
  int rdlength;
  char nbuf [MAXDNAME];

  nsswap (ns_header);

	/* Ignore invalid packets... */
  if (ns_header -> id != ns_query_id)
    {
      printf ("Unexpected NS message; id = %d\n", ns_header -> id);
      return;
    }

	/* We have our response, so shut down the protocol... */
  ns_callback = (void (*) (char *))0;
  ns_query_id = 0;
  stop_pushing ();

	/* Parse the response... */
  dptr = base;

	/* Skip over the query name... */
  dptr += skipname (dptr);
	/* Skip over the query type and the query class. */
  dptr += 2 * sizeof (short);

	/* Skip over the reply name... */
  dptr += skipname (dptr);
	/* Extract the numeric fields: */
  GETSHORT (type, dptr);
  GETSHORT (class, dptr);
  GETLONG (ttl, dptr);
  GETSHORT (rdlength, dptr);

  switch (type)
    {
    case T_A:
      printf ("A record; value is ");
      printiaddr (dptr);
      if (callback)
	(*callback) (dptr);
      break;

    case T_CNAME:
    case T_PTR:
      copy_out_name (base, dptr, nbuf);
      printf ("Domain name; value is %s\n", nbuf);
      if (callback)
	(*callback) (nbuf);
      return;

#ifdef T_TXT
    case T_TXT:
      printf ("Text string; value is %s\n", dptr);
      if (callback)
	(*callback) (dptr);
      break;
#endif /* T_TXT */

    default:
      printf ("unhandled type: %x\n", type);
    }

  if (callback)
    (*callback) ((char *)1);
}

#if BYTE_ORDER == LITTLE_ENDIAN
nsswap (hdr)
     HEADER *hdr;
{
  shortswap (hdr -> opcode);
  shortswap (hdr -> qdcount);
  shortswap (hdr -> ancount);
  shortswap (hdr -> nscount);
  shortswap (hdr -> arcount);
}
#endif
