/* parse.c

   Common parser code for dhcpd and dhclient. */

/*
 * Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.
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
"$Id: parse.c,v 1.7 1998/06/25 03:07:51 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

/* Skip to the semicolon ending the current statement.   If we encounter
   braces, the matching closing brace terminates the statement.   If we
   encounter a right brace but haven't encountered a left brace, return
   leaving the brace in the token buffer for the caller.   If we see a
   semicolon and haven't seen a left brace, return.   This lets us skip
   over:

   	statement;
	statement foo bar { }
	statement foo bar { statement { } }
	statement}
 
	...et cetera. */

void skip_to_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	int brace_count = 0;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			if (brace_count) {
				token = next_token (&val, cfile);
				if (!--brace_count)
					return;
			} else
				return;
		} else if (token == LBRACE) {
			brace_count++;
		} else if (token == SEMI && !brace_count) {
			token = next_token (&val, cfile);
			return;
		} else if (token == EOL) {
			/* EOL only happens when parsing /etc/resolv.conf,
			   and we treat it like a semicolon because the
			   resolv.conf file is line-oriented. */
			token = next_token (&val, cfile);
			return;
		}
		token = next_token (&val, cfile);
	} while (token != EOF);
}

int parse_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;

	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return 0;
	}
	return 1;
}

/* string-parameter :== STRING SEMI */

char *parse_string (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	char *s;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("filename must be a string");
		skip_to_semi (cfile);
		return (char *)0;
	}
	s = (char *)malloc (strlen (val) + 1);
	if (!s)
		error ("no memory for string %s.", val);
	strcpy (s, val);

	if (!parse_semi (cfile))
		return (char *)0;
	return s;
}

/*
 * hostname :== IDENTIFIER
 *		| IDENTIFIER DOT
 *		| hostname DOT IDENTIFIER
 */

char *parse_host_name (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	int len = 0;
	char *s;
	char *t;
	pair c = (pair)0;
	
	/* Read a dotted hostname... */
	do {
		/* Read a token, which should be an identifier. */
		token = peek_token (&val, cfile);
		if (!is_identifier (token) && token != NUMBER)
			break;
		token = next_token (&val, cfile);

		/* Store this identifier... */
		if (!(s = (char *)malloc (strlen (val) + 1)))
			error ("can't allocate temp space for hostname.");
		strcpy (s, val);
		c = cons ((caddr_t)s, c);
		len += strlen (s) + 1;
		/* Look for a dot; if it's there, keep going, otherwise
		   we're done. */
		token = peek_token (&val, cfile);
		if (token == DOT)
			token = next_token (&val, cfile);
	} while (token == DOT);

	/* Assemble the hostname together into a string. */
	if (!(s = (char *)malloc (len)))
		error ("can't allocate space for hostname.");
	t = s + len;
	*--t = 0;
	while (c) {
		pair cdr = c -> cdr;
		int l = strlen ((char *)(c -> car));
		t -= l;
		memcpy (t, (char *)(c -> car), l);
		/* Free up temp space. */
		free (c -> car);
		free (c);
		c = cdr;
		if (t != s)
			*--t = '.';
	}
	return s;
}

/* ip-addr-or-hostname :== ip-address | hostname
   ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.   If uniform is zero, put in
   an expr_substring node to limit hostnames that evaluate to more
   than one IP address. */

struct expression *parse_ip_addr_or_hostname (cfile, uniform)
	FILE *cfile;
	int uniform;
{
	char *val;
	int token;
	unsigned char addr [4];
	int len = sizeof addr;
	char *name;
	struct expression *rv;

	token = peek_token (&val, cfile);
	if (is_identifier (token)) {
		name = parse_host_name (cfile);
		if (!name)
			return (struct expression *)0;
		rv = make_host_lookup (name);
		if (!uniform)
			rv = make_limit (rv, 4);
	} else if (token == NUMBER) {
		if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
			return (struct expression *)0;
		rv = make_const_data (addr, len, 0, 0);
	} else {
		if (token != RBRACE && token != LBRACE)
			token = next_token (&val, cfile);
		parse_warn ("%s (%d): expecting IP address or hostname",
			    val, token);
		if (token != SEMI)
			skip_to_semi (cfile);
		return (struct expression *)0;
	}

	return rv;
}	
	
/*
 * ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
 */

int parse_ip_addr (cfile, addr)
	FILE *cfile;
	struct iaddr *addr;
{
	char *val;
	int token;

	addr -> len = 4;
	if (parse_numeric_aggregate (cfile, addr -> iabuf,
				     &addr -> len, DOT, 10, 8))
		return 1;
	return 0;
}	

/*
 * hardware-parameter :== HARDWARE hardware-type colon-seperated-hex-list SEMI
 * hardware-type :== ETHERNET | TOKEN_RING
 */

void parse_hardware_param (cfile, hardware)
	FILE *cfile;
	struct hardware *hardware;
{
	char *val;
	int token;
	int hlen;
	unsigned char *t;

	token = next_token (&val, cfile);
	switch (token) {
	      case ETHERNET:
		hardware -> htype = HTYPE_ETHER;
		break;
	      case TOKEN_RING:
		hardware -> htype = HTYPE_IEEE802;
		break;
	      default:
		parse_warn ("expecting a network hardware type");
		skip_to_semi (cfile);
		return;
	}

	/* Parse the hardware address information.   Technically,
	   it would make a lot of sense to restrict the length of the
	   data we'll accept here to the length of a particular hardware
	   address type.   Unfortunately, there are some broken clients
	   out there that put bogus data in the chaddr buffer, and we accept
	   that data in the lease file rather than simply failing on such
	   clients.   Yuck. */
	hlen = 0;
	t = parse_numeric_aggregate (cfile, (unsigned char *)0, &hlen,
				     COLON, 16, 8);
	if (!t)
		return;
	if (hlen > sizeof hardware -> haddr) {
		free (t);
		parse_warn ("hardware address too long");
	} else {
		hardware -> hlen = hlen;
		memcpy ((unsigned char *)&hardware -> haddr [0],
			t, hardware -> hlen);
		free (t);
	}
	
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("expecting semicolon.");
		skip_to_semi (cfile);
	}
}

/* lease-time :== NUMBER SEMI */

void parse_lease_time (cfile, timep)
	FILE *cfile;
	TIME *timep;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("Expecting numeric lease time");
		skip_to_semi (cfile);
		return;
	}
	convert_num ((unsigned char *)timep, val, 10, 32);
	/* Unswap the number - convert_num returns stuff in NBO. */
	*timep = ntohl (*timep); /* XXX */

	parse_semi (cfile);
}

/* No BNF for numeric aggregates - that's defined by the caller.  What
   this function does is to parse a sequence of numbers seperated by
   the token specified in seperator.  If max is zero, any number of
   numbers will be parsed; otherwise, exactly max numbers are
   expected.  Base and size tell us how to internalize the numbers
   once they've been tokenized. */

unsigned char *parse_numeric_aggregate (cfile, buf,
					max, seperator, base, size)
	FILE *cfile;
	unsigned char *buf;
	int *max;
	int seperator;
	int base;
	int size;
{
	char *val;
	int token;
	unsigned char *bufp = buf, *s, *t;
	int count = 0;
	pair c = (pair)0;

	if (!bufp && *max) {
		bufp = (unsigned char *)malloc (*max * size / 8);
		if (!bufp)
			error ("can't allocate space for numeric aggregate");
	} else
		s = bufp;

	do {
		if (count) {
			token = peek_token (&val, cfile);
			if (token != seperator) {
				if (!*max)
					break;
				if (token != RBRACE && token != LBRACE)
					token = next_token (&val, cfile);
				parse_warn ("too few numbers.");
				if (token != SEMI)
					skip_to_semi (cfile);
				return (unsigned char *)0;
			}
			token = next_token (&val, cfile);
		}
		token = next_token (&val, cfile);

		if (token == EOF) {
			parse_warn ("unexpected end of file");
			break;
		}

		/* Allow NUMBER_OR_NAME if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_NAME)) {
			parse_warn ("expecting numeric value.");
			skip_to_semi (cfile);
			return (unsigned char *)0;
		}
		/* If we can, convert the number now; otherwise, build
		   a linked list of all the numbers. */
		if (s) {
			convert_num (s, val, base, size);
			s += size / 8;
		} else {
			t = (unsigned char *)malloc (strlen (val) + 1);
			if (!t)
				error ("no temp space for number.");
			strcpy ((char *)t, val);
			c = cons ((caddr_t)t, c);
		}
	} while (++count != *max);

	/* If we had to cons up a list, convert it now. */
	if (c) {
		bufp = (unsigned char *)malloc (count * size / 8);
		if (!bufp)
			error ("can't allocate space for numeric aggregate.");
		s = bufp + count - size / 8;
		*max = count;
	}
	while (c) {
		pair cdr = c -> cdr;
		convert_num (s, (char *)(c -> car), base, size);
		s -= size / 8;
		/* Free up temp space. */
		free (c -> car);
		free (c);
		c = cdr;
	}
	return bufp;
}

void convert_num (buf, str, base, size)
	unsigned char *buf;
	char *str;
	int base;
	int size;
{
	char *ptr = str;
	int negative = 0;
	u_int32_t val = 0;
	int tval;
	int max;

	if (*ptr == '-') {
		negative = 1;
		++ptr;
	}

	/* If base wasn't specified, figure it out from the data. */
	if (!base) {
		if (ptr [0] == '0') {
			if (ptr [1] == 'x') {
				base = 16;
				ptr += 2;
			} else if (isascii (ptr [1]) && isdigit (ptr [1])) {
				base = 8;
				ptr += 1;
			} else {
				base = 10;
			}
		} else {
			base = 10;
		}
	}

	do {
		tval = *ptr++;
		/* XXX assumes ASCII... */
		if (tval >= 'a')
			tval = tval - 'a' + 10;
		else if (tval >= 'A')
			tval = tval - 'A' + 10;
		else if (tval >= '0')
			tval -= '0';
		else {
			warn ("Bogus number: %s.", str);
			break;
		}
		if (tval >= base) {
			warn ("Bogus number: %s: digit %d not in base %d\n",
			      str, tval, base);
			break;
		}
		val = val * base + tval;
	} while (*ptr);

	if (negative)
		max = (1 << (size - 1));
	else
		max = (1 << (size - 1)) + ((1 << (size - 1)) - 1);
	if (val > max) {
		switch (base) {
		      case 8:
			warn ("value %s%o exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      case 16:
			warn ("value %s%x exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      default:
			warn ("value %s%u exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		}
	}

	if (negative) {
		switch (size) {
		      case 8:
			*buf = -(unsigned long)val;
			break;
		      case 16:
			putShort (buf, -(unsigned long)val);
			break;
		      case 32:
			putLong (buf, -(unsigned long)val);
			break;
		      default:
			warn ("Unexpected integer size: %d\n", size);
			break;
		}
	} else {
		switch (size) {
		      case 8:
			*buf = (u_int8_t)val;
			break;
		      case 16:
			putUShort (buf, (u_int16_t)val);
			break;
		      case 32:
			putULong (buf, val);
			break;
		      default:
			warn ("Unexpected integer size: %d\n", size);
			break;
		}
	}
}

/*
 * date :== NUMBER NUMBER SLASH NUMBER SLASH NUMBER 
 *		NUMBER COLON NUMBER COLON NUMBER SEMI
 *
 * Dates are always in GMT; first number is day of week; next is
 * year/month/day; next is hours:minutes:seconds on a 24-hour
 * clock.
 */

TIME parse_date (cfile)
	FILE *cfile;
{
	struct tm tm;
	int guess;
	char *val;
	int token;
	static int months [11] = { 31, 59, 90, 120, 151, 181,
					  212, 243, 273, 304, 334 };

	/* Day of week... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of week expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_wday = atoi (val);

	/* Year... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric year expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Note: the following is not a Y2K bug - it's a Y1.9K bug.   Until
	   somebody invents a time machine, I think we can safely disregard
	   it.   This actually works around a stupid Y2K bug that was present
	   in a very early beta release of dhcpd. */
	tm.tm_year = atoi (val);
	if (tm.tm_year > 1900)
		tm.tm_year -= 1900;

	/* Slash seperating year from month... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating year from month.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_mon = atoi (val) - 1;

	/* Slash seperating month from day... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating month from day.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_mday = atoi (val);

	/* Hour... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric hour expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_hour = atoi (val);

	/* Colon seperating hour from minute... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_min = atoi (val);

	/* Colon seperating minute from second... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_sec = atoi (val);
	tm.tm_isdst = 0;

	/* XXX */ /* We assume that mktime does not use tm_yday. */
	tm.tm_yday = 0;

	/* Make sure the date ends in a semicolon... */
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return 0;
	}

	/* Guess the time value... */
	guess = ((((((365 * (tm.tm_year - 70) +	/* Days in years since '70 */
		      (tm.tm_year - 69) / 4 +	/* Leap days since '70 */
		      (tm.tm_mon		/* Days in months this year */
		       ? months [tm.tm_mon - 1]
		       : 0) +
		      (tm.tm_mon > 1 &&		/* Leap day this year */
		       !((tm.tm_year - 72) & 3)) +
		      tm.tm_mday - 1) * 24) +	/* Day of month */
		    tm.tm_hour) * 60) +
		  tm.tm_min) * 60) + tm.tm_sec;

	/* This guess could be wrong because of leap seconds or other
	   weirdness we don't know about that the system does.   For
	   now, we're just going to accept the guess, but at some point
	   it might be nice to do a successive approximation here to
	   get an exact value.   Even if the error is small, if the
	   server is restarted frequently (and thus the lease database
	   is reread), the error could accumulate into something
	   significant. */

	return guess;
}

/*
 * option-name :== IDENTIFIER |
 		   IDENTIFIER . IDENTIFIER
 */

struct option *parse_option_name (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	char *vendor;
	struct universe *universe;
	struct option *option;

	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (struct option *)0;
	}
	vendor = malloc (strlen (val) + 1);
	if (!vendor)
		error ("no memory for vendor information.");
	strcpy (vendor, val);
	token = peek_token (&val, cfile);
	if (token == DOT) {
		/* Go ahead and take the DOT token... */
		token = next_token (&val, cfile);

		/* The next token should be an identifier... */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier after '.'");
			if (token != SEMI)
				skip_to_semi (cfile);
			return (struct option *)0;
		}

		/* Look up the option name hash table for the specified
		   vendor. */
		universe = ((struct universe *)
			    hash_lookup (&universe_hash,
					 (unsigned char *)vendor, 0));
		/* If it's not there, we can't parse the rest of the
		   declaration. */
		if (!universe) {
			parse_warn ("no vendor named %s.", vendor);
			skip_to_semi (cfile);
			return (struct option *)0;
		}
	} else {
		/* Use the default hash table, which contains all the
		   standard dhcp option names. */
		val = vendor;
		universe = &dhcp_universe;
	}

	/* Look up the actual option info... */
	option = (struct option *)hash_lookup (universe -> hash,
					       (unsigned char *)val, 0);

	/* If we didn't get an option structure, it's an undefined option. */
	if (!option) {
		if (val == vendor)
			parse_warn ("no option named %s", val);
		else
			parse_warn ("no option named %s for vendor %s",
				    val, vendor);
		skip_to_semi (cfile);
		return (struct option *)0;
	}

	/* Free the initial identifier token. */
	free (vendor);
	return option;
}

/*
 * colon-seperated-hex-list :== NUMBER |
 *				NUMBER COLON colon-seperated-hex-list
 */

unsigned char *parse_cshl (cfile, plen)
	FILE *cfile;
	int *plen;
{
	char ibuf [128];
	int ilen = 0;
	int tlen = 0;
	struct option_tag *sl = (struct option_tag *)0;
	struct option_tag *next, **last = &sl;
	int token;
	char *val;
	unsigned char *rv, *rvp;

	do {
		token = next_token (&val, cfile);
		if (token != NUMBER && token != NUMBER_OR_NAME) {
			parse_warn ("expecting hexadecimal number.");
			skip_to_semi (cfile);
			for (; sl; sl = next) {
				next = sl -> next;
				dfree (sl, "parse_cshl");
			}
			return (unsigned char *)0;
		}
		if (ilen == sizeof ibuf) {
			next = (struct option_tag *)
				dmalloc (ilen - 1 +
					 sizeof (struct option_tag),
					 "parse_cshl");
			if (!next)
				error ("no memory for string list.");
			memcpy (next -> data, ibuf, ilen);
			*last = next;
			last = &next -> next;
			tlen += ilen;
			ilen = 0;
		}
		convert_num (&ibuf [ilen++], val, 16, 8);

		token = peek_token (&val, cfile);
		if (token != COLON)
			break;
		token = next_token (&val, cfile);
	} while (1);

	rv = dmalloc (tlen + ilen, "parse_cshl");
	if (!rv)
		error ("no memory to store octet data.");
	rvp = rv;
	while (sl) {
		next = sl -> next;
		memcpy (rvp, sl -> data, sizeof ibuf);
		rvp += sizeof ibuf;
		dfree (sl, "parse_cshl");
		sl = next;
	}
	
	memcpy (rvp, ibuf, ilen);
	*plen = ilen + tlen;
	return rv;
}

/*
 * executable-statements :== executable-statement executable-statements |
 *			     executable-statement
 *
 * executable-statement :==
 *	IF if-statement |
 * 	ADD class-name SEMI |
 *	BREAK SEMI |
 *	OPTION option-parameter SEMI |
 *	SUPERSEDE option-parameter SEMI |
 *	PREPEND option-parameter SEMI |
 *	APPEND option-parameter SEMI
 */

struct executable_statement *parse_executable_statements (cfile, lose)
	FILE *cfile;
	int *lose;
{
	struct executable_statement *head, **next;

	next = &head;
	while ((*next = parse_executable_statement (cfile, lose)))
		next = &((*next) -> next);
	if (!lose)
		return head;
	return (struct executable_statement *)0;
}

struct executable_statement *parse_executable_statement (cfile, lose)
	FILE *cfile;
	int *lose;
{
	int token;
	char *val;
	struct executable_statement *stmt, base;
	struct class *cta;
	struct option *option;

	switch (peek_token (&val, cfile)) {
	      case IF:
		stmt = parse_if_statement (cfile, lose);
		return stmt;
	      case ADD:
		token = next_token (&val, cfile);
		if (token != STRING) {
			parse_warn ("expecting class name.");
			skip_to_semi (cfile);
			*lose = 1;
			return (struct executable_statement *)0;
		}
		cta = find_class (val);
		if (!cta) {
			parse_warn ("unknown class %s.", val);
			skip_to_semi (cfile);
			*lose = 1;
			return (struct executable_statement *)0;
		}
		if (!parse_semi (cfile)) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		memset (&base, 0, sizeof base);
		base.op = add_statement;
		base.data.add = cta;
		break;

	      case BREAK:
		token = next_token (&val, cfile);
		if (!parse_semi (cfile)) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		memset (&base, 0, sizeof base);
		base.op = break_statement;
		break;

	      case OPTION:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       supersede_option_statement);

	      case DEFAULT:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       default_option_statement);

	      case PREPEND:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       prepend_option_statement);

	      case APPEND:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       append_option_statement);

	      default:
		*lose = 0;
		return (struct executable_statement *)0;
	}

	stmt = ((struct executable_statement *)
		dmalloc (sizeof (struct executable_statement),
			 "parse_executable_statement"));
	if (!stmt)
		error ("no memory for new statement.");
	*stmt = base;
	return stmt;
}

/*
 * if-statement :== boolean-expression LBRACE executable-statements RBRACE
 *						else-statement
 *
 * else-statement :== <null> |
 *		      ELSE LBRACE executable-statements RBRACE |
 *		      ELSE IF if-statement |
 *		      ELSIF if-statement
 */

struct executable_statement *parse_if_statement (cfile, lose)
	FILE *cfile;
	int *lose;
{
	int token;
	char *val;
	struct executable_statement *stmt;
	struct expression *if_condition;
	struct executable_statement *true, *false;

	token = next_token (&val, cfile);
	if_condition = parse_boolean_expression (cfile, lose);
	if (!if_condition) {
		if (!*lose)
			parse_warn ("boolean expression expected.");
		return (struct executable_statement *)0;
	}
	token = next_token (&val, cfile);
	if (token != LBRACE) {
		parse_warn ("left brace expected.");
		skip_to_semi (cfile);
		*lose = 1;
		return (struct executable_statement *)0;
	}
	true = parse_executable_statements (cfile, lose);
	if (*lose)
		return (struct executable_statement *)0;
	token = next_token (&val, cfile);
	if (token != RBRACE) {
		parse_warn ("right brace expected.");
		skip_to_semi (cfile);
		*lose = 1;
		return (struct executable_statement *)0;
	}
	token = peek_token (&val, cfile);
	if (token == ELSE) {
		token = next_token (&val, cfile);
		token = peek_token (&val, cfile);
		if (token == IF) {
			token = next_token (&val, cfile);
			false = parse_if_statement (cfile, lose);
			if (*lose)
				return (struct executable_statement *)0;
		} else if (token != LBRACE) {
			parse_warn ("left brace or if expected.");
			skip_to_semi (cfile);
			*lose = 1;
			return (struct executable_statement *)0;
		} else {
			token = next_token (&val, cfile);
			false = parse_executable_statement (cfile, lose);
			if (*lose)
				return (struct executable_statement *)0;
		}
	} else if (token == ELSIF) {
		token = next_token (&val, cfile);
		false = parse_if_statement (cfile, lose);
		if (*lose)
			return (struct executable_statement *)0;
	} else
		false = (struct executable_statement *)0;
	
	stmt = ((struct executable_statement *)
		dmalloc (sizeof (struct executable_statement),
			 "parse_if_statement"));
	if (!stmt)
		error ("no memory for if statement.");
	memset (stmt, 0, sizeof *stmt);
	stmt -> op = if_statement;
	stmt -> data.ie.expr = if_condition;
	stmt -> data.ie.true = true;
	stmt -> data.ie.false = false;
	return stmt;
}

/*
 * boolean_expression :== CHECK STRING |
 *  			  NOT boolean-expression |
 *			  data-expression EQUAL data-expression |
 *			  boolean-expression AND boolean-expression |
 *			  boolean-expression OR boolean-expression
 */
   			  

struct expression *parse_boolean_expression (cfile, lose)
	FILE *cfile;
	int *lose;
{
	int token;
	char *val;
	struct collection *col;
	struct expression buf, *rv;
	struct expression *left, *right;

	token = peek_token (&val, cfile);

	/* Check for unary operators... */
	switch (token) {
	      case CHECK:
		token = next_token (&val, cfile);
		token = next_token (&val, cfile);
		if (token != STRING) {
			parse_warn ("string expected.");
			skip_to_semi (cfile);
			*lose = 1;
			return (struct expression *)0;
		}
		for (col = collections; col; col = col -> next)
			if (!strcmp (col -> name, val))
				break;
		if (!col) {
			parse_warn ("unknown collection.");
			*lose = 1;
			return (struct expression *)0;
		}
		buf.op = expr_check;
		buf.data.check = col;
		goto have_expr;

	      case NOT:
		token = next_token (&val, cfile);
		buf.op = expr_not;
		buf.data.not = parse_boolean_expression (cfile, lose);
		if (!buf.data.not) {
			if (!*lose) {
				parse_warn ("match expression expected");
				skip_to_semi (cfile);
			}
			*lose = 1;
			return (struct expression *)0;
		}
		goto have_expr;
	}

	/* If we're going to find an expression at this point, it must
	   involve a binary operator seperating two subexpressions. */
	left = parse_data_expression (cfile, lose);
	if (!left)
		return left;
	token = peek_token (&val, cfile);
	switch (token) {
	      case EQUAL:
		buf.op = expr_equal;
		break;
	      case AND:
		buf.op = expr_and;
		break;
	      case OR:
		buf.op = expr_or;
		break;
	      default:
		parse_warn ("Expecting a boolean expression.");
		skip_to_semi (cfile);
		*lose = 1;
		return (struct expression *)0;
	}
	token = next_token (&val, cfile);

	/* Now find the RHS of the expression. */
	right = parse_data_expression (cfile, lose);
	if (!right) {
		if (!*lose) {
			if (buf.op == expr_equal)
				parse_warn ("Expecting a data expression.");
			else
				parse_warn ("Expecting a boolean expression.");
			skip_to_semi (cfile);
		}
		return right;
	}

	/* Store the LHS and RHS. */
	buf.data.equal [0] = left;
	buf.data.equal [1] = right;

      have_expr:
	rv = new_expression ("parse_boolean_expression");
	if (!rv)
		error ("No memory for boolean expression.");
	*rv = buf;
	return rv;
}	

/*
 * data_expression :== SUBSTRING LPAREN data-expression COMMA
 *					numeric-expression COMMA
 *					numeric-expression RPAREN |
 *		       SUFFIX LPAREN data_expression COMMA
 *		       		     numeric-expression |
 *		       OPTION option_name |
 *		       HARDWARE |
 *		       PACKET LPAREN numeric-expression COMMA
 *				     numeric-expression RPAREN |
 *		       STRING |
 *		       colon_seperated_hex_list
 */

struct expression *parse_data_expression (cfile, lose)
	FILE *cfile;
	int *lose;
{
	int token;
	char *val;
	struct collection *col;
	struct expression buf, *rv;
	struct expression *left, *right;
	struct option *option;

	token = peek_token (&val, cfile);

	switch (token) {
	      case SUBSTRING:
		token = next_token (&val, cfile);
		buf.op = expr_substring;

		token = next_token (&val, cfile);
		if (token != LPAREN) {
		      nolparen:
			parse_warn ("left parenthesis expected.");
			*lose = 1;
			return (struct expression *)0;
		}

		rv = parse_data_expression (cfile, lose);
		if (!rv) {
		      nodata:
			parse_warn ("expecting data expression.");
			skip_to_semi (cfile);
			*lose = 1;
			return (struct expression *)0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA) {
		      nocomma:
			parse_warn ("comma expected.");
			*lose = 1;
			return (struct expression *)0;
		}

		left = parse_numeric_expression (cfile, lose);
		if (!left) {
		      nonum:
			if (!*lose) {
				parse_warn ("expecting numeric expression.");
				skip_to_semi (cfile);
				*lose = 1;
			}
			return (struct expression *)0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		right = parse_numeric_expression (cfile, lose);
		if (!right)
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN) {
		      norparen:
			parse_warn ("right parenthesis expected.");
			*lose = 1;
			return (struct expression *)0;
		}
		return make_substring (rv, left, right);

	      case SUFFIX:
		token = next_token (&val, cfile);
		buf.op = expr_suffix;

		token = next_token (&val, cfile);
		if (token != LPAREN)
			goto nolparen;

		buf.data.suffix.expr = parse_data_expression (cfile, lose);
		if (!buf.data.suffix.expr)
			goto nodata;

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		buf.data.suffix.len = parse_numeric_expression (cfile, lose);
		if (!buf.data.suffix.len)
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN)
			goto norparen;
		goto have_expr;

	      case OPTION:
		token = next_token (&val, cfile);
		buf.op = expr_option;
		buf.data.option = parse_option_name (cfile);
		if (!buf.data.option) {
			*lose = 1;
			return (struct expression *)0;
		}
		goto have_expr;

	      case HARDWARE:
		token = next_token (&val, cfile);
		buf.op = expr_hardware;
		goto have_expr;

	      case PACKET:
		token = next_token (&val, cfile);
		buf.op = expr_packet;

		token = next_token (&val, cfile);
		if (token != LPAREN)
			goto nolparen;

		buf.data.packet.offset =
			parse_numeric_expression (cfile, lose);
		if (!buf.data.packet.offset)
			goto nonum;

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		buf.data.packet.len =
			parse_numeric_expression (cfile, lose);
		if (!buf.data.substring.len)
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN)
			goto norparen;
		goto have_expr;
		
	      case STRING:
		token = next_token (&val, cfile);
		return make_const_data (val, strlen (val), 1, 1);

	      case NUMBER:
	      case NUMBER_OR_NAME:
		buf.op = expr_const_data;
		memset (&buf.data, 0, sizeof buf.data);
		buf.data.const_data.data =
			parse_cshl (cfile, &buf.data.const_data.len);
		goto have_expr;

	      default:
		return (struct expression *)0;
	}

      have_expr:
	rv = (struct expression *)dmalloc (sizeof (struct expression),
					   "parse_boolean_expression");
	if (!rv)
		error ("No memory for boolean expression.");
	*rv = buf;
	return rv;
}

/*
 * numeric-expression :== EXTRACT_INT LPAREN data-expression
 *					     COMMA number RPAREN |
 *			  NUMBER
 */

struct expression *parse_numeric_expression (cfile, lose)
	FILE *cfile;
	int *lose;
{
	int token;
	char *val;
	struct collection *col;
	struct expression buf, *rv;
	struct expression *left, *right;
	struct option *option;

	token = peek_token (&val, cfile);

	switch (token) {
	      case EXTRACT_INT:
		token = next_token (&val, cfile);	

		token = next_token (&val, cfile);
		if (token != LPAREN) {
			parse_warn ("left parenthesis expected.");
			*lose = 1;
			return (struct expression *)0;
		}

		buf.data.extract_int.expr =
			parse_data_expression (cfile, lose);
		if (!buf.data.extract_int.expr) {
			parse_warn ("expecting data expression.");
			skip_to_semi (cfile);
			*lose = 1;
			return (struct expression *)0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA) {
			parse_warn ("comma expected.");
			*lose = 1;
			return (struct expression *)0;
		}

		token = next_token (&val, cfile);
		if (token != NUMBER) {
			parse_warn ("number expected.");
			*lose = 1;
			return (struct expression *)0;
		}
		buf.data.extract_int.width = (struct expression *)0;
		switch (atoi (val)) {
		      case 8:
			buf.op = expr_extract_int8;
			break;

		      case 16:
			buf.op = expr_extract_int16;
			break;

		      case 32:
			buf.op = expr_extract_int32;
			break;

		      default:
			parse_warn ("unsupported integer size %d", atoi (val));
			*lose = 1;
			skip_to_semi (cfile);
			return (struct expression *)0;
		}

		token = next_token (&val, cfile);
		if (token != RPAREN) {
			parse_warn ("right parenthesis expected.");
			*lose = 1;
			return (struct expression *)0;
		}
		goto have_expr;
	
	      case NUMBER:
		buf.op = expr_const_int;
		buf.data.const_int = atoi (val);
		goto have_expr;

	      default:
		return (struct expression *)0;
	}

      have_expr:
	rv = (struct expression *)dmalloc (sizeof (struct expression),
					   "parse_boolean_expression");
	if (!rv)
		error ("No memory for boolean expression.");
	*rv = buf;
	return rv;
}

/* option-statement :== identifier DOT identifier <syntax> SEMI
		      | identifier <syntax> SEMI

   Option syntax is handled specially through format strings, so it
   would be painful to come up with BNF for it.   However, it always
   starts as above and ends in a SEMI. */

struct executable_statement *parse_option_statement (cfile, lookups,
						     option, op)
	FILE *cfile;
	int lookups;
	struct option *option;
	enum statement_op op;
{
	char *val;
	int token;
	char *fmt;
	struct expression *expr = (struct expression *)0;
	int lose;
	struct executable_statement *stmt;

	token = peek_token (&val, cfile);
	if (token == SEMI) {
		/* Eat the semicolon... */
		token = next_token (&val, cfile);
		expr = make_const_data (0, 0, 0, 0);
		goto done;
	}

	/* See if there's a data expression, and if so, use it rather than
	   the standard format. */
	expr = ((struct expression *)parse_data_expression (cfile, &lose));

	/* Found a data expression, but it was bogus? */
	if (lose)
		return (struct executable_statement *)0;
		
	/* We found one. */
	if (expr)
		goto done;

	/* Parse the option data... */
	do {
		/* Set a flag if this is an array of a simple type (i.e.,
		   not an array of pairs of IP addresses, or something
		   like that. */
		int uniform = option -> format [1] == 'A';

		for (fmt = option -> format; *fmt; fmt++) {
			if (*fmt == 'A')
				break;
			expr = parse_option_token (cfile, fmt,
						   expr, uniform, lookups);
		}
		if (*fmt == 'A') {
			token = peek_token (&val, cfile);
			if (token == COMMA) {
				token = next_token (&val, cfile);
				continue;
			}
			break;
		}
	} while (*fmt == 'A');

      done:
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return (struct executable_statement *)0;
	}
	stmt = ((struct executable_statement *)
		dmalloc (sizeof *stmt, "parse_option_statement"));
	stmt -> op = op;
	stmt -> data.option = option_cache (expr, option);
	return stmt;
}

struct expression *parse_option_token (cfile, fmt, expr, uniform, lookups)
	FILE *cfile;
	char *fmt;
	struct expression *expr;
	int uniform;
	int lookups;
{
	char *val;
	int token;
	struct expression *t;
	unsigned char buf [4];
	int len;
	unsigned char *ob;
	struct iaddr addr;

	switch (*fmt) {
	      case 'X':
		token = peek_token (&val, cfile);
		if (token == NUMBER_OR_NAME || token == NUMBER) {
			ob = parse_cshl (cfile, &len);
			return make_concat (expr,
					    make_const_data (ob, len, 0, 0));
		} else if (token == STRING) {
			token = next_token (&val, cfile);
			return make_concat (expr,
					    make_const_data ((unsigned char *)
							     val,
							     strlen (val),
							     1, 1));
		} else {
			parse_warn ("expecting string %s.",
				    "or hexadecimal data");
			skip_to_semi (cfile);
			return (struct expression *)0;
		}
		break;
		
	      case 't': /* Text string... */
		token = next_token (&val, cfile);
		if (token != STRING && !is_identifier (token)) {
			parse_warn ("expecting string.");
			if (token != SEMI)
				skip_to_semi (cfile);
			return (struct expression *)0;
		}
		return make_concat (expr,
				    make_const_data ((unsigned char *)
						     val, strlen (val), 1, 1));
		break;
		
	      case 'I': /* IP address or hostname. */
		if (lookups)
			t = parse_ip_addr_or_hostname (cfile, uniform);
		else {
			if (!parse_ip_addr (cfile, &addr))
				return (struct expression *)0;
			t = make_const_data (addr.iabuf, addr.len, 0, 1);
		}
		if (!t)
			return (struct expression *)0;
		return make_concat (expr, t);
		break;
		
	      case 'L': /* Unsigned 32-bit integer... */
	      case 'l':	/* Signed 32-bit integer... */
		token = next_token (&val, cfile);
		if (token != NUMBER) {
		      need_number:
			parse_warn ("expecting number.");
			if (token != SEMI)
				skip_to_semi (cfile);
			return (struct expression *)0;
		}
		convert_num (buf, val, 0, 32);
		return make_concat (expr, make_const_data (buf, 4, 0, 1));
		break;
	      case 's':	/* Signed 16-bit integer. */
	      case 'S':	/* Unsigned 16-bit integer. */
		token = next_token (&val, cfile);
		if (token != NUMBER)
			goto need_number;
		convert_num (buf, val, 0, 16);
		return make_concat (expr, make_const_data (buf, 2, 0, 1));
		break;
	      case 'b':	/* Signed 8-bit integer. */
	      case 'B':	/* Unsigned 8-bit integer. */
		token = next_token (&val, cfile);
		if (token != NUMBER)
			goto need_number;
		convert_num (buf, val, 0, 8);
		return make_concat (expr, make_const_data (buf, 1, 0, 1));
		break;
	      case 'f': /* Boolean flag. */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier.");
		      bad_flag:
			if (token != SEMI)
				skip_to_semi (cfile);
			return (struct expression *)0;
		}
		if (!strcasecmp (val, "true")
		    || !strcasecmp (val, "on"))
			buf [0] = 1;
		else if (!strcasecmp (val, "false")
			 || !strcasecmp (val, "off"))
			buf [0] = 0;
		else {
			parse_warn ("expecting boolean.");
			goto bad_flag;
		}
		return make_concat (expr, make_const_data (buf, 1, 0, 1));
		break;
	      default:
		warn ("Bad format %c in parse_option_param.",
		      *fmt);
		skip_to_semi (cfile);
		return (struct expression *)0;
	}
}
