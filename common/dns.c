/* dns.c

   Domain Name Service subroutines. */

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
"$Id: dns.c,v 1.11 1999/03/16 05:50:34 mellon Exp $ Copyright (c) 1997 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "arpa/nameser.h"

int dns_protocol_initialized;
int dns_protocol_fd;

static int addlabel PROTO ((u_int8_t *, char *));
static int skipname PROTO ((u_int8_t *));
static int copy_out_name PROTO ((u_int8_t *, u_int8_t *, char *));
static int nslookup PROTO ((u_int8_t, char *, int, u_int16_t, u_int16_t));
static int zonelookup PROTO ((u_int8_t, char *, int, u_int16_t));
u_int16_t dns_port;

#define DNS_QUERY_HASH_SIZE	293
struct dns_query *dns_query_hash [DNS_QUERY_HASH_SIZE];

/* Initialize the DNS protocol. */

void dns_startup ()
{
	struct servent *srv;
	struct sockaddr_in from;

	/* Only initialize icmp once. */
	if (dns_protocol_initialized)
		log_fatal ("attempted to reinitialize dns protocol");
	dns_protocol_initialized = 1;

	/* Get the protocol number (should be 1). */
	srv = getservbyname ("domain", "tcp");
	if (srv)
		dns_port = srv -> s_port;
	else
		dns_port = htons (53);

	/* Get a socket for the DNS protocol. */
	dns_protocol_fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dns_protocol_fd < 0)
		log_fatal ("unable to create dns socket: %m");

	first_name_server ();

	add_protocol ("dns", dns_protocol_fd, dns_packet, 0);
}

/* Label manipulation stuff; see RFC1035, page 28 section 4.1.2 and
   page 30, section 4.1.4. */

/* addlabel copies a label into the specified buffer, putting the length of
   the label in the first character, the contents of the label in subsequent
   characters, and returning the length of the conglomeration. */

static int addlabel (buf, label)
	u_int8_t *buf;
	char *label;
{
	*buf = strlen (label);
	memcpy (buf + 1, label, *buf);
	return *buf + 1;
}

/* skipname skips over all of the labels in a single domain name,
   returning the length of the domain name. */

static int skipname (label)
     u_int8_t *label;
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

static int copy_out_name (base, name, buf)
     u_int8_t *base;
     u_int8_t *name;
     char *buf;
{
	if (*name & INDIR_MASK) {
		int offset = (*name & ~INDIR_MASK) + (*name + 1);
		return copy_out_name (base, base + offset, buf);
	}
	if (!*name) {
		*buf = 0;
		return 1;
	}
	memcpy (buf, name + 1, *name);
	*(buf + *name) = '.';
	return (*name + 1
		+ copy_out_name (base, name + *name + 1, buf + *name + 1));
}

/* Compute a hash on the question. */

static INLINE u_int32_t dns_hash_question (struct dns_question *question)
{
	u_int32_t sum;
	u_int32_t remainder;
	u_int32_t *p = (u_int32_t *)question;
	u_int8_t *s;

	/* First word. */
	sum = *p++;
	s = (u_int8_t *)p;

	remainder = 0;
	while (s [0]) {
		remainder = s [0];
		if (s [1]) {
			remainder = (remainder << 8) + s [1];
			if (s [2]) {
				remainder = (remainder << 8) + s [2];
				if (s [3])
					remainder = (remainder << 8) + s [3];
				else
					goto done;
			} else
				goto done;
		} else {
		      done:
			sum += remainder;
			break;
		}
		if ((sum & 0x80000000) && (remainder & 0x80000000))
			++sum;
		sum += remainder;
		s += 4;
	}

	while (sum > DNS_QUERY_HASH_SIZE) {
		remainder = sum / DNS_QUERY_HASH_SIZE;
		sum = sum % DNS_QUERY_HASH_SIZE;
		while (remainder) {
			sum += remainder % DNS_QUERY_HASH_SIZE;
			remainder /= DNS_QUERY_HASH_SIZE;
		}
	} 

	return sum;
}

/* Find a query that matches the specified name.  If one can't be
   found, and new is nonzero, allocate one, hash it in, and save the
   question.  Otherwise, if new is nonzero, free() the question.
   Return the query if one was found or allocated. */

struct dns_query *find_dns_query (question, new)
	struct dns_question *question;
	int new;
{
	int hash = dns_hash_question (question);
	struct dns_query *q;

	for (q = dns_query_hash [hash]; q; q = q -> next) {
		if (q -> question -> type == question -> type &&
		    q -> question -> class == question -> class &&
		    !strcmp ((char *)q -> question -> data,
			     (char *)question -> data))
			break;
	}
	if (q || !new) {
		if (new)
			free (question);
		return q;
	}

	/* Allocate and zap a new query. */
	q = (struct dns_query *)malloc (sizeof (struct dns_query));
	memset (q, 0, sizeof *q);

	/* All we need to set up is the question and the hash. */
	q -> question = question;
	q -> next = dns_query_hash [hash];
	dns_query_hash [hash] = q;
	q -> hash = hash;
	return q;
}

/* Free up all memory associated with a DNS query and remove it from the
   query hash. */

void destroy_dns_query (query)
	struct dns_query *query;
{
	struct dns_query *q;

	/* Free up attached free data. */
	if (query -> question)
		free (query -> question);
	if (query -> answer)
		free (query -> answer);
	if (query -> query)
		free (query -> query);

	/* Remove query from hash table. */
	if (dns_query_hash [query -> hash] == query)
		dns_query_hash [query -> hash] = query -> next;
	else {
		for (q = dns_query_hash [query -> hash];
		     q -> next && q -> next != query; q = q -> next)
			;
		if (q -> next)
			q -> next = query -> next;
	}

	/* Free the query structure. */
	free (query);
}

/* ns_inaddr_lookup constructs a PTR lookup query for an internet address -
   e.g., 1.200.9.192.in-addr.arpa.   It then passes it on to ns_query for
   completion. */

struct dns_query *ns_inaddr_lookup (inaddr, wakeup)
	struct iaddr inaddr;
	struct dns_wakeup *wakeup;
{
	unsigned char query [512];
	unsigned char *s;
	unsigned char *label;
	int i;
	unsigned char c;
	struct dns_question *question;

	/* First format the query in the internal format. */
	sprintf ((char *)query, "%d.%d.%d.%d.in-addr.arpa.",
		 inaddr.iabuf [0], inaddr.iabuf [1],
		 inaddr.iabuf [2], inaddr.iabuf [3]);

	question = (struct dns_question *)malloc (strlen ((char *)query) +
						  sizeof *question);
	if (!question)
		return (struct dns_query *)-1;
	question -> type = T_PTR;
	question -> class = C_IN;
	strcpy ((char *)question -> data, (char *)query);

	/* Now format the query for the name server. */
	s = query;

	/* Copy out the digits. */
	for (i = 3; i >= 0; --i) {
		label = s++;
		sprintf ((char *)s, "%d", inaddr.iabuf [i]);
		*label = strlen ((char *)s);
		s += *label;
	}
	s += addlabel (s, "in-addr");
	s += addlabel (s, "arpa");
	*s++ = 0;

	/* Set the query type. */
	putUShort (s, T_PTR);
	s += sizeof (u_int16_t);

	/* Set the query class. */
	putUShort (s, C_IN);
	s += sizeof (u_int16_t);

	return ns_query (question, query, s - query, wakeup);
}

/* Try to satisfy a query out of the local cache.  If no answer has
   been cached, and if there isn't already a query pending on this
   question, send it.  If the query can be immediately satisfied,
   a pointer to the dns_query structure is returned.  If the query
   can't even be made for some reason, (struct dns_query *)-1 is
   returned.  Otherwise, the null pointer is returned, indicating that
   a wakeup will be performed later when the answer comes back. */

struct dns_query *ns_query (question, formatted_query, len, wakeup)
	struct dns_question *question;
	unsigned char *formatted_query;
	int len;
	struct dns_wakeup *wakeup;
{
	HEADER *hdr;
	struct dns_query *query;
	unsigned char *s;
	unsigned char buf [512];

	/* If the query won't fit, don't bother setting it up. */
	if (len > 255) {
		free (question);
		return (struct dns_query *)-1;
	}

	/* See if there's already a query for this name, and allocate a
	   query if none exists. */
	query = find_dns_query (question, 1);

	/* If we can't allocate a query, report that the query failed. */
	if (!query)
		return (struct dns_query *)-1;

	/* If the query has already been answered, return it. */
	if (query -> expiry > cur_time)
		return query;

	/* The query hasn't yet been answered, so we have to wait, one
	   way or another.   Put the wakeup on the list. */
	if (wakeup) {
		wakeup -> next = query -> wakeups;
		query -> wakeups = wakeup;
	}

	/* If the query has already been sent, but we don't yet have
	   an answer, we're done. */
	if (query -> sent)
		return (struct dns_query *)0;

	/* Construct a header... */
	hdr = (HEADER *)buf;
	memset (hdr, 0, sizeof *hdr);
	hdr -> id = query -> id;
	hdr -> rd = 1;
	hdr -> opcode = QUERY;
	hdr -> qdcount = htons (1);

	/* Copy the formatted name into the buffer. */
	s = (unsigned char *)hdr + 1;
	memcpy (s, formatted_query, len);

	/* Figure out how long the whole message is */
	s += len;
	query -> len = s - buf;

	/* Save the raw query data. */
	query -> query = malloc (len);
	if (!query -> query) {
		destroy_dns_query (query);
		return (struct dns_query *)-1;
	}
	memcpy (query -> query, buf, query -> len);

	/* Flag the query as having been sent. */
	query -> sent = 1;

	/* Send the query. */
	dns_timeout (query);

	/* No answer yet, obviously. */
	return (struct dns_query *)0;
}

/* Retransmit a DNS query. */

void dns_timeout (qv)
	void *qv;
{
	struct dns_query *query = qv;
	int status;

	/* Choose the server to send to. */
	if (!query -> next_server)
		query -> next_server = first_name_server ();

	/* Send the query. */
	if (query -> next_server)
		status = sendto (dns_protocol_fd,
				 (char *)query -> query, query -> len, 0,
				 ((struct sockaddr *)&query ->
				  next_server -> addr),
				 sizeof query -> next_server -> addr);
	else
		status = -1;

	/* Look for the next server... */
	query -> next_server = query -> next_server -> next;

	/* If this is our first time, backoff one second. */
	if (!query -> backoff)
		query -> backoff = 1;

	/* If the send failed, don't advance the backoff. */
	else if (status < 0)
		;

	/* If we haven't run out of servers to try, don't backoff. */
	else if (query -> next_server)
		;

	/* If we haven't backed off enough yet, back off some more. */
	else if (query -> backoff < 30)
		query -> backoff += random() % query -> backoff;

	/* Set up the timeout. */
	add_timeout (cur_time + query -> backoff, dns_timeout, query);
}

/* Process a reply from a name server. */

void dns_packet (protocol)
	struct protocol *protocol;
{
	HEADER *ns_header;
	struct sockaddr_in from;
	struct dns_wakeup *wakeup;
	unsigned char buf [512];
	union {
		unsigned char u [512];
		struct dns_question q;
	} qbuf;
	unsigned char *base;
	unsigned char *dptr, *name;
	u_int16_t type;
	u_int16_t class;
	TIME ttl;
	u_int16_t rdlength;
	int len, status;
	int i;
	struct dns_query *query;

	len = sizeof from;
	status = recvfrom (protocol -> fd, (char *)buf, sizeof buf, 0,
			  (struct sockaddr *)&from, &len);
	if (status < 0) {
		log_error ("dns_packet: %m");
		return;
	}

	/* Response is too long? */
	if (len > 512) {
		log_error ("dns_packet: dns message too long (%d)", len);
		return;
	}

	ns_header = (HEADER *)buf;
	base = (unsigned char *)(ns_header + 1);

	/* Parse the response... */
	dptr = base;

	/* If this is a response to a query from us, there should have
           been only one query. */
	if (ntohs (ns_header -> qdcount) != 1) {
		log_error ("Bogus DNS answer packet from %s claims %d queries.\n",
		      inet_ntoa (from.sin_addr),
		      ntohs (ns_header -> qdcount));
		return;
	}

	/* Find the start of the name in the query. */
	name = dptr;

	/* Skip over the name. */
	dptr += copy_out_name (name, name, (char *)qbuf.q.data);

	/* Skip over the query type and query class. */
	qbuf.q.type = getUShort (dptr);
	dptr += sizeof (u_int16_t);
	qbuf.q.class = getUShort (dptr);
	dptr += sizeof (u_int16_t);

	/* See if we asked this question. */
	query = find_dns_query (&qbuf.q, 0);
	if (!query) {
log_error ("got answer for question %s from DNS, which we didn't ask.",
qbuf.q.data);
		return;
	}

log_info ("got answer for question %s from DNS", qbuf.q.data);

	/* Wake up everybody who's waiting. */
	for (wakeup = query -> wakeups; wakeup; wakeup = wakeup -> next) {
		(*wakeup -> func) (query);
	}
}
