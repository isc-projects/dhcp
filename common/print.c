/* print.c

   Turn data structures into printable text. */

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
"$Id: print.c,v 1.22 1999/04/05 16:18:22 mellon Exp $ Copyright (c) 1995, 1996, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

char *print_hw_addr (htype, hlen, data)
	int htype;
	int hlen;
	unsigned char *data;
{
	static char habuf [49];
	char *s;
	int i;

	if (htype == 0 || hlen == 0) {
		strcpy (habuf, "<null>");
	} else {
		s = habuf;
		for (i = 0; i < hlen; i++) {
			sprintf (s, "%02x", data [i]);
			s += strlen (s);
			*s++ = ':';
		}
		*--s = 0;
	}
	return habuf;
}

void print_lease (lease)
	struct lease *lease;
{
	struct tm *t;
	char tbuf [32];

	log_debug ("  Lease %s",
	       piaddr (lease -> ip_addr));
	
	t = gmtime (&lease -> starts);
	strftime (tbuf, sizeof tbuf, "%Y/%m/%d %H:%M:%S", t);
	log_debug ("  start %s", tbuf);
	
	t = gmtime (&lease -> ends);
	strftime (tbuf, sizeof tbuf, "%Y/%m/%d %H:%M:%S", t);
	log_debug ("  end %s", tbuf);
	
	t = gmtime (&lease -> timestamp);
	strftime (tbuf, sizeof tbuf, "%Y/%m/%d %H:%M:%S", t);
	log_debug ("  stamp %s", tbuf);
	
	log_debug ("    hardware addr = %s",
	       print_hw_addr (lease -> hardware_addr.htype,
			       lease -> hardware_addr.hlen,
			       lease -> hardware_addr.haddr));
	log_debug ("  host %s  ",
	       lease -> host ? lease -> host -> name : "<none>");
}	

#if defined (DEBUG)
void dump_packet (tp)
	struct packet *tp;
{
	struct dhcp_packet *tdp = tp -> raw;

	log_debug ("packet length %d", tp -> packet_length);
	log_debug ("op = %d  htype = %d  hlen = %d  hops = %d",
	       tdp -> op, tdp -> htype, tdp -> hlen, tdp -> hops);
	log_debug ("xid = %x  secs = %d  flags = %x",
	       tdp -> xid, tdp -> secs, tdp -> flags);
	log_debug ("ciaddr = %s", inet_ntoa (tdp -> ciaddr));
	log_debug ("yiaddr = %s", inet_ntoa (tdp -> yiaddr));
	log_debug ("siaddr = %s", inet_ntoa (tdp -> siaddr));
	log_debug ("giaddr = %s", inet_ntoa (tdp -> giaddr));
	log_debug ("chaddr = %02.2x:%02.2x:%02.2x:%02.2x:%02.2x:%02.2x",
	       ((unsigned char *)(tdp -> chaddr)) [0],
	       ((unsigned char *)(tdp -> chaddr)) [1],
	       ((unsigned char *)(tdp -> chaddr)) [2],
	       ((unsigned char *)(tdp -> chaddr)) [3],
	       ((unsigned char *)(tdp -> chaddr)) [4],
	       ((unsigned char *)(tdp -> chaddr)) [5]);
	log_debug ("filename = %s", tdp -> file);
	log_debug ("server_name = %s", tdp -> sname);
	if (tp -> options_valid) {
		int i;

		for (i = 0; i < 256; i++) {
			if (tp -> options [i].data)
				log_debug ("  %s = %s",
					dhcp_options [i].name,
					pretty_print_option
					(i, tp -> options [i].data,
					 tp -> options [i].len, 1, 1));
		}
	}
	log_debug ("");
}
#endif

void dump_raw (buf, len)
	unsigned char *buf;
	int len;
{
	int i;
	char lbuf [80];
	int lbix = 0;

	lbuf [0] = 0;

	for (i = 0; i < len; i++) {
		if ((i & 15) == 0) {
			if (lbix)
				log_info (lbuf);
			sprintf (lbuf, "%03x:", i);
			lbix = 4;
		} else if ((i & 7) == 0)
			lbuf [lbix++] = ' ';
		sprintf (&lbuf [lbix], " %02x", buf [i]);
		lbix += 3;
	}
	log_info (lbuf);
}

void hash_dump (table)
	struct hash_table *table;
{
	int i;
	struct hash_bucket *bp;

	if (!table)
		return;

	for (i = 0; i < table -> hash_count; i++) {
		if (!table -> buckets [i])
			continue;
		log_info ("hash bucket %d:", i);
		for (bp = table -> buckets [i]; bp; bp = bp -> next) {
			if (bp -> len)
				dump_raw (bp -> name, bp -> len);
			else
				log_info ((char *)bp -> name);
		}
	}
}

#define HBLEN 60

#define DECLARE_HEX_PRINTER(x)						      \
char *print_hex##x (len, data, limit)					      \
	int len;							      \
	u_int8_t *data;							      \
{									      \
									      \
	static char hex_buf##x [HBLEN + 1];				      \
	int i;								      \
									      \
	if (limit > HBLEN)						      \
		limit = HBLEN;						      \
									      \
	for (i = 0; i < (limit - 2) && i < len; i++) {			      \
		if (!isascii (data [i]) || !isprint (data [i])) {	      \
			for (i = 0; i < limit / 3 && i < len; i++) {	      \
				sprintf (&hex_buf##x [i * 3],		      \
					 "%02x:", data [i]);		      \
			}						      \
			hex_buf##x [i * 3 - 1] = 0;			      \
			return hex_buf##x;				      \
		}							      \
	}								      \
	hex_buf##x [0] = '"';						      \
	i = len;							      \
	if (i > limit - 2)						      \
		i = limit - 2;						      \
	memcpy (&hex_buf##x [1], data, i);				      \
	hex_buf##x [i + 1] = '"';					      \
	hex_buf##x [i + 2] = 0;						      \
	return hex_buf##x;						      \
}

DECLARE_HEX_PRINTER (_1)
DECLARE_HEX_PRINTER (_2)
DECLARE_HEX_PRINTER (_3)

#define DQLEN	80

char *print_dotted_quads (len, data)
	int len;
	u_int8_t *data;
{
	static char dq_buf [DQLEN + 1];
	int i;
	char *s, *last;

	s = &dq_buf [0];
	last = s;
	
	i = 0;

	do {
		sprintf (s, "%d.%d.%d.%d, ",
			 data [i], data [i + 1], data [i + 2], data [i + 3]);
		s += strlen (s);
		i += 4;
	} while ((s - &dq_buf [0] > DQLEN - 21) &&
		 i + 3 < len);
	if (i == len)
		s [-2] = 0;
	else
		strcpy (s, "...");
	return dq_buf;
}

char *print_dec_1 (val)
	int val;
{
	static char vbuf [32];
	sprintf (vbuf, "%d", val);
	return vbuf;
}

char *print_dec_2 (val)
	int val;
{
	static char vbuf [32];
	sprintf (vbuf, "%d", val);
	return vbuf;
}

static int print_subexpression PROTO ((struct expression *, char *, int));

static int print_subexpression (expr, buf, len)
	struct expression *expr;
	char *buf;
	int len;
{
	int rv;
	char *s;
	
	switch (expr -> op) {
	      case expr_none:
		if (len > 3) {
			strcpy (buf, "nil");
			return 3;
		}
		break;
		  
	      case expr_match:
		if (len > 7) {
			strcpy (buf, "(match)");
			return 7;
		}
		break;

	      case expr_check:
		rv = 10 + strlen (expr -> data.check -> name);
		if (len > rv) {
			sprintf (buf, "(check %s)",
				 expr -> data.check -> name);
			return rv;
		}
		break;

	      case expr_equal:
		if (len > 6) {
			rv = 4;
			strcpy (buf, "(eq ");
			rv += print_subexpression (expr -> data.equal [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.equal [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_substring:
		if (len > 11) {
			rv = 8;
			strcpy (buf, "(substr ");
			rv += print_subexpression (expr -> data.substring.expr,
						   buf + rv, len - rv - 3);
			buf [rv++] = ' ';
			rv += print_subexpression
				(expr -> data.substring.offset,
				 buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.substring.len,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_suffix:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(substr ");
			rv += print_subexpression (expr -> data.suffix.expr,
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.suffix.len,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_concat:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(concat ");
			rv += print_subexpression (expr -> data.concat [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.concat [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_host_lookup:
		rv = 15 + strlen (expr -> data.host_lookup -> hostname);
		if (len > rv) {
			sprintf (buf, "(dns-lookup %s)",
				 expr -> data.host_lookup -> hostname);
			return rv;
		}
		break;

	      case expr_and:
		if (len > 7) {
			rv = 5;
			strcpy (buf, "(and ");
			rv += print_subexpression (expr -> data.and [0],
						buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.and [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_or:
		if (len > 6) {
			rv = 4;
			strcpy (buf, "(or ");
			rv += print_subexpression (expr -> data.or [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.or [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_not:
		if (len > 6) {
			rv = 5;
			strcpy (buf, "(not ");
			rv += print_subexpression (expr -> data.not,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_option:
		rv = 10 + (strlen (expr -> data.option -> name) +
			   strlen (expr -> data.option -> universe -> name));
		if (len > rv) {
			sprintf (buf, "(option %s.%s)",
				 expr -> data.option -> universe -> name,
				 expr -> data.option -> name);
			return rv;
		}
		break;

	      case expr_hardware:
		if (len > 10) {
			strcpy (buf, "(hardware)");
			return 10;
		}
		break;

	      case expr_packet:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(substr ");
			rv += print_subexpression (expr -> data.packet.offset,
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.packet.len,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_const_data:
		s = print_hex_1 (expr -> data.const_data.len,
				 expr -> data.const_data.data, len);
		rv = strlen (s);
		if (rv >= len)
			rv = len - 1;
		strncpy (buf, s, rv);
		buf [rv] = 0;
		return rv;

	      case expr_encapsulate:
		rv = 13;
		strcpy (buf, "(encapsulate ");
		rv += expr -> data.encapsulate.len;
		if (rv + 2 > len)
			rv = len - 2;
		strncpy (buf, expr -> data.encapsulate.data, rv - 13);
		buf [rv++] = ')';
		buf [rv++] = 0;
		break;

	      case expr_extract_int8:
		if (len > 7) {
			rv = 6;
			strcpy (buf, "(int8 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_extract_int16:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(int16 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_extract_int32:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(int32 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_const_int:
		s = print_dec_1 (expr -> data.const_int);
		rv = strlen (s);
		if (len > rv) {
			strcpy (buf, s);
			return rv;
		}
		break;

	      case expr_exists:
		rv = 10 + (strlen (expr -> data.option -> name) +
			   strlen (expr -> data.option -> universe -> name));
		if (len > rv) {
			sprintf (buf, "(exists %s.%s)",
				 expr -> data.option -> universe -> name,
				 expr -> data.option -> name);
			return rv;
		}
		break;
	}
	return 0;
}

void print_expression (name, expr)
	char *name;
	struct expression *expr;
{
	char buf [1024];

	print_subexpression (expr, buf, sizeof buf);
	log_info ("%s: %s", name, buf);
}

