/* parse.c

   Common parser code for dhcpd and dhclient. */

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
"$Id: parse.c,v 1.21 1999/04/12 22:09:24 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
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
	skip_to_rbrace (cfile, 0);
}

void skip_to_rbrace (cfile, brace_count)
	FILE *cfile;
	int brace_count;
{
	enum dhcp_token token;
	char *val;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			if (brace_count) {
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
	enum dhcp_token token;
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
	enum dhcp_token token;
	char *s;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("filename must be a string");
		skip_to_semi (cfile);
		return (char *)0;
	}
	s = (char *)malloc (strlen (val) + 1);
	if (!s)
		log_fatal ("no memory for string %s.", val);
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
	enum dhcp_token token;
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
			log_fatal ("can't allocate temp space for hostname.");
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
		log_fatal ("can't allocate space for hostname.");
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

int parse_ip_addr_or_hostname (expr, cfile, uniform)
	struct expression **expr;
	FILE *cfile;
	int uniform;
{
	char *val;
	enum dhcp_token token;
	unsigned char addr [4];
	int len = sizeof addr;
	char *name;
	struct expression *x = (struct expression *)0;

	token = peek_token (&val, cfile);
	if (is_identifier (token)) {
		name = parse_host_name (cfile);
		if (!name)
			return 0;
		if (!make_host_lookup (expr, name))
			return 0;
		if (!uniform) {
			if (!make_limit (&x, *expr, 4))
				return 0;
			expression_dereference (expr,
						"parse_ip_addr_or_hostname");
			*expr = x;
		}
	} else if (token == NUMBER) {
		if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
			return 0;
		return make_const_data (expr, addr, len, 0, 1);
	} else {
		if (token != RBRACE && token != LBRACE)
			token = next_token (&val, cfile);
		parse_warn ("%s (%d): expecting IP address or hostname",
			    val, token);
		if (token != SEMI)
			skip_to_semi (cfile);
		return 0;
	}

	return 1;
}	
	
/*
 * ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
 */

int parse_ip_addr (cfile, addr)
	FILE *cfile;
	struct iaddr *addr;
{
	char *val;
	enum dhcp_token token;

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
	enum dhcp_token token;
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
	      case FDDI:
		hardware -> htype = HTYPE_FDDI;
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
		if (hlen < sizeof hardware -> haddr)
			memset (&hardware -> haddr [hlen], 0,
				(sizeof hardware -> haddr) - hlen);
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
	enum dhcp_token token;

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
	enum dhcp_token token;
	unsigned char *bufp = buf, *s, *t;
	int count = 0;
	pair c = (pair)0;

	if (!bufp && *max) {
		bufp = (unsigned char *)malloc (*max * size / 8);
		if (!bufp)
			log_fatal ("can't allocate space for numeric aggregate");
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
				log_fatal ("no temp space for number.");
			strcpy ((char *)t, val);
			c = cons ((caddr_t)t, c);
		}
	} while (++count != *max);

	/* If we had to cons up a list, convert it now. */
	if (c) {
		bufp = (unsigned char *)malloc (count * size / 8);
		if (!bufp)
			log_fatal ("can't allocate space for numeric aggregate.");
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
			log_error ("Bogus number: %s.", str);
			break;
		}
		if (tval >= base) {
			log_error ("Bogus number: %s: digit %d not in base %d\n",
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
			log_error ("value %s%o exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      case 16:
			log_error ("value %s%x exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      default:
			log_error ("value %s%u exceeds max (%d) for precision.",
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
			log_error ("Unexpected integer size: %d\n", size);
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
			log_error ("Unexpected integer size: %d\n", size);
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
	enum dhcp_token token;
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
	if (!parse_semi (cfile))
		return 0;

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

struct option *parse_option_name (cfile, allocate)
	FILE *cfile;
	int allocate;
{
	char *val;
	enum dhcp_token token;
	char *uname;
	struct universe *universe;
	struct option *option;

	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (struct option *)0;
	}
	uname = malloc (strlen (val) + 1);
	if (!uname)
		log_fatal ("no memory for uname information.");
	strcpy (uname, val);
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
		   uname. */
		universe = ((struct universe *)
			    hash_lookup (&universe_hash,
					 (unsigned char *)uname, 0));
		/* If it's not there, we can't parse the rest of the
		   declaration. */
		if (!universe) {
			parse_warn ("no option space named %s.", uname);
			skip_to_semi (cfile);
			return (struct option *)0;
		}
	} else {
		/* Use the default hash table, which contains all the
		   standard dhcp option names. */
		val = uname;
		universe = &dhcp_universe;
	}

	/* Look up the actual option info... */
	option = (struct option *)hash_lookup (universe -> hash,
					       (unsigned char *)val, 0);

	/* If we didn't get an option structure, it's an undefined option. */
	if (!option) {
		/* If we've been told to allocate, that means that this
		   (might) be an option code definition, so we'll create
		   an option structure just in case. */
		if (allocate) {
			option = new_option ("parse_option_name");
			if (val == uname)
				option -> name = val;
			else {
				free (uname);
				option -> name = dmalloc (strlen (val) + 1,
							  "parse_option_name");
				if (!option -> name)
					log_fatal ("no memory for option %s.%s",
					           universe -> name, val);
				strcpy (option -> name, val);
			}
			option -> universe = universe;
			option -> code = -1;
			return option;
		}
		if (val == uname)
			parse_warn ("no option named %s", val);
		else
			parse_warn ("no option named %s in space %s",
				    val, uname);
		skip_to_semi (cfile);
		return (struct option *)0;
	}

	/* Free the initial identifier token. */
	free (uname);
	return option;
}

/* IDENTIFIER SEMI */

void parse_option_space_decl (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	struct universe **ua, *nu;

	next_token (&val, cfile);	/* Discard the SPACE token, which was
					   checked by the caller. */
	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier.");
		skip_to_semi (cfile);
		return;
	}
	nu = new_universe ("parse_option_space_decl");
	if (!nu)
		log_fatal ("No memory for new option space.");

	/* Set up the server option universe... */
	nu -> name = dmalloc (strlen (val) + 1, "parse_option_space_decl");
	if (!nu -> name)
		log_fatal ("No memory for new option space name.");
	strcpy (nu -> name, val);
	nu -> lookup_func = lookup_hashed_option;
	nu -> option_state_dereference =
		hashed_option_state_dereference;
	nu -> get_func = hashed_option_get;
	nu -> set_func = hashed_option_set;
	nu -> save_func = save_hashed_option;
	nu -> delete_func = delete_hashed_option;
	nu -> encapsulate = hashed_option_space_encapsulate;
	nu -> length_size = 1;
	nu -> tag_size = 1;
	nu -> store_tag = putUChar;
	nu -> store_length = putUChar;
	nu -> index = universe_count++;
	if (nu -> index >= universe_max) {
		ua = dmalloc (universe_max * 2 * sizeof *ua,
			      "parse_option_space_decl");
		if (!ua)
			log_fatal ("No memory to expand option space array.");
		memcpy (ua, universes, universe_max * sizeof *ua);
		universe_max *= 2;
		dfree (universes, "parse_option_space_decl");
		universes = ua;
	}
	universes [nu -> index] = nu;
	nu -> hash = new_hash ();
	if (!nu -> hash)
		log_fatal ("Can't allocate %s option hash table.", nu -> name);
	add_hash (&universe_hash,
		  (unsigned char *)nu -> name, 0, (unsigned char *)nu);
	parse_semi (cfile);
}

/* This is faked up to look good right now.   Ideally, this should do a
   recursive parse and allow arbitrary data structure definitions, but for
   now it just allows you to specify a single type, an array of single types,
   a sequence of types, or an array of sequences of types.

   ocd :== NUMBER EQUALS ocsd SEMI

   ocsd :== ocsd_type |
	    ocsd_type_sequence |
	    ARRAY OF ocsd_type |
	    ARRAY OF ocsd_type_sequence

   ocsd_type :== BOOLEAN |
		 INTEGER NUMBER |
		 SIGNED INTEGER NUMBER |
		 UNSIGNED INTEGER NUMBER |
		 IP-ADDRESS |
		 TEXT |
		 STRING

   ocsd_type_sequence :== LBRACE ocsd_types RBRACE

   ocsd_type :== ocsd_type |
		 ocsd_types ocsd_type */

int parse_option_code_definition (cfile, option)
	FILE *cfile;
	struct option *option;
{
	char *val;
	enum dhcp_token token;
	int arrayp = 0;
	int recordp = 0;
	int no_more_in_record = 0;
	char tokbuf [128];
	int tokix = 0;
	char type;
	int code;
	int is_signed;
	
	/* Parse the option code. */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("expecting option code number.");
		skip_to_semi (cfile);
		return 0;
	}
	option -> code = atoi (val);

	token = next_token (&val, cfile);
	if (token != EQUAL) {
		parse_warn ("expecting \"=\"");
		skip_to_semi (cfile);
		return 0;
	}

	/* See if this is an array. */
	token = next_token (&val, cfile);
	if (token == ARRAY) {
		token = next_token (&val, cfile);
		if (token != OF) {
			parse_warn ("expecting \"of\".");
			skip_to_semi (cfile);
			return 0;
		}
		arrayp = 1;
		token = next_token (&val, cfile);
	}

	if (token == LBRACE) {
		recordp = 1;
		token = next_token (&val, cfile);
	}

	/* At this point we're expecting a data type. */
      next_type:
	switch (token) {
	      case BOOLEAN:
		type = 'f';
		break;
	      case INTEGER:
		is_signed = 1;
	      parse_integer:
		token = next_token (&val, cfile);
		if (token != NUMBER) {
			parse_warn ("expecting number.");
			skip_to_rbrace (cfile, recordp);
			if (recordp)
				skip_to_semi (cfile);
			return 0;
		}
		switch (atoi (val)) {
		      case 8:
			type = is_signed ? 'b' : 'B';
			break;
		      case 16:
			type = is_signed ? 's' : 'S';
			break;
		      case 32:
			type = is_signed ? 'l' : 'L';
			break;
		      default:
			parse_warn ("%s bit precision is not supported.", val);
			skip_to_rbrace (cfile, recordp);
			if (recordp)
				skip_to_semi (cfile);
			return 0;
		}
		break;
	      case SIGNED:
		is_signed = 1;
	      parse_signed:
		token = next_token (&val, cfile);
		if (token != INTEGER) {
			parse_warn ("expecting \"integer\" keyword.");
			skip_to_rbrace (cfile, recordp);
			if (recordp)
				skip_to_semi (cfile);
			return 0;
		}
		goto parse_integer;
	      case UNSIGNED:
		is_signed = 0;
		goto parse_signed;

	      case IP_ADDRESS:
		type = 'I';
		break;
	      case TEXT:
		type = 't';
	      no_arrays:
		if (arrayp) {
			parse_warn ("arrays of text strings not %s",
				    "yet supported.");
			skip_to_rbrace (cfile, recordp);
			if (recordp)
				skip_to_semi (cfile);
			return 0;
		}
		no_more_in_record = 1;
		break;
	      case STRING:
		type = 'X';
		goto no_arrays;

	      default:
		parse_warn ("unknown data type %s", val);
		skip_to_rbrace (cfile, recordp);
		if (recordp)
			skip_to_semi (cfile);
		return 0;
	}

	if (tokix == sizeof tokbuf) {
		parse_warn ("too many types in record.");
		skip_to_rbrace (cfile, recordp);
		if (recordp)
			skip_to_semi (cfile);
		return 0;
	}
	tokbuf [tokix++] = type;

	if (recordp) {
		token = next_token (&val, cfile);
		if (token == COMMA) {
			if (no_more_in_record) {
				parse_warn ("%s must be at end of record.",
					    type == 't' ? "text" : "string");
				skip_to_rbrace (cfile, 1);
				if (recordp)
					skip_to_semi (cfile);
				return 0;
			}
			token = next_token (&val, cfile);
			goto next_type;
		}
		if (token != RBRACE) {
			parse_warn ("expecting right brace.");
			skip_to_rbrace (cfile, 1);
			if (recordp)
				skip_to_semi (cfile);
			return 0;
		}
	}
	if (!parse_semi (cfile)) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		if (recordp)
			skip_to_semi (cfile);
		return 0;
	}
	option -> format = dmalloc (tokix + arrayp + 1,
				    "parse_option_code_definition");
	if (!option -> format)
		log_fatal ("no memory for option format.");
	memcpy (option -> format, tokbuf, tokix);
	if (arrayp)
		option -> format [tokix++] = 'A';
	option -> format [tokix] = 0;
	if (option -> universe -> options [option -> code]) {
		/* XXX Free the option, but we can't do that now because they
		   XXX may start out static. */
	}
	option -> universe -> options [option -> code] = option;
	add_hash (option -> universe -> hash,
		  (unsigned char *)option -> name, 0, (unsigned char *)option);
	return 1;
}

/*
 * colon-seperated-hex-list :== NUMBER |
 *				NUMBER COLON colon-seperated-hex-list
 */

int parse_cshl (data, cfile)
	struct data_string *data;
	FILE *cfile;
{
	u_int8_t ibuf [128];
	int ilen = 0;
	int tlen = 0;
	struct option_tag *sl = (struct option_tag *)0;
	struct option_tag *next, **last = &sl;
	enum dhcp_token token;
	char *val;
	unsigned char *rvp;

	do {
		token = next_token (&val, cfile);
		if (token != NUMBER && token != NUMBER_OR_NAME) {
			parse_warn ("expecting hexadecimal number.");
			skip_to_semi (cfile);
			for (; sl; sl = next) {
				next = sl -> next;
				dfree (sl, "parse_cshl");
			}
			return 0;
		}
		if (ilen == sizeof ibuf) {
			next = (struct option_tag *)
				dmalloc (ilen - 1 +
					 sizeof (struct option_tag),
					 "parse_cshl");
			if (!next)
				log_fatal ("no memory for string list.");
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

	if (!buffer_allocate (&data -> buffer, tlen + ilen, "parse_cshl"))
		log_fatal ("no memory to store octet data.");
	data -> data = &data -> buffer -> data [0];
	data -> len = tlen + ilen;
	data -> terminated = 0;

	rvp = &data -> data [0];
	while (sl) {
		next = sl -> next;
		memcpy (rvp, sl -> data, sizeof ibuf);
		rvp += sizeof ibuf;
		dfree (sl, "parse_cshl");
		sl = next;
	}
	
	memcpy (rvp, ibuf, ilen);
	return 1;
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
	if (!*lose)
		return head;
	return (struct executable_statement *)0;
}

struct executable_statement *parse_executable_statement (cfile, lose)
	FILE *cfile;
	int *lose;
{
	enum dhcp_token token;
	char *val;
	struct executable_statement *stmt, base;
	struct class *cta;
	struct option *option;
	struct option_cache *cache;

	token = peek_token (&val, cfile);
	switch (token) {
	      case IF:
		next_token (&val, cfile);
		stmt = parse_if_statement (cfile, lose);
		return stmt;
	      case ADD:
		token = next_token (&val, cfile);
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

	      case SEND:
		*lose = 1;
		parse_warn ("send not appropriate here.");
		skip_to_semi (cfile);
		return (struct executable_statement *)0;

	      case SUPERSEDE:
	      case OPTION:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile, 0);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       supersede_option_statement);

	      case ALLOW:
	      case DENY:
		token = next_token (&val, cfile);
		cache = (struct option_cache *)0;
		if (!parse_allow_deny (&cache, cfile,
				       token == ALLOW ? 1 : 0))
			return (struct executable_statement *)0;
		memset (&base, 0, sizeof base);
		base.op = supersede_option_statement;
		base.data.option = cache;
		break;

	      case DEFAULT:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile, 0);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       default_option_statement);

	      case PREPEND:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile, 0);
		if (!option) {
			*lose = 1;
			return (struct executable_statement *)0;
		}
		return parse_option_statement (cfile, 1, option,
					       prepend_option_statement);

	      case APPEND:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile, 0);
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
		log_fatal ("no memory for new statement.");
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
	enum dhcp_token token;
	char *val;
	struct executable_statement *stmt;
	struct expression *if_condition;
	struct executable_statement *true, *false;

	if_condition = (struct expression *)0;
	if (!parse_boolean_expression (&if_condition, cfile, lose)) {
		if (!*lose)
			parse_warn ("boolean expression expected.");
		return (struct executable_statement *)0;
	}
#if defined (DEBUG_EXPRESSION_PARSE)
	print_expression ("if condition", if_condition);
#endif
	token = next_token (&val, cfile);
	if (token != LBRACE) {
		parse_warn ("left brace expected.");
		skip_to_semi (cfile);
		*lose = 1;
		return (struct executable_statement *)0;
	}
	true = parse_executable_statements (cfile, lose);
	token = next_token (&val, cfile);
	if (*lose) {
		/* Try to even things up. */
		do {
			token = next_token (&val, cfile);
		} while (token != EOF && token != RBRACE);
		return (struct executable_statement *)0;
	}
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
			false = parse_executable_statements (cfile, lose);
			if (*lose)
				return (struct executable_statement *)0;
			token = next_token (&val, cfile);
			if (token != RBRACE) {
				parse_warn ("right brace expected.");
				skip_to_semi (cfile);
				*lose = 1;
				return (struct executable_statement *)0;
			}
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
		log_fatal ("no memory for if statement.");
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
 *			  EXISTS OPTION-NAME
 */
   			  
int parse_boolean_expression (expr, cfile, lose)
	struct expression **expr;
	FILE *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_boolean,
			       (struct expression **)0, expr_none))
		return 0;

	if (!is_boolean_expression (*expr)) {
		parse_warn ("Expecting a boolean expression.");
		*lose = 1;
		return 0;
	}
	return 1;
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

int parse_data_expression (expr, cfile, lose)
	struct expression **expr;
	FILE *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_data,
			       (struct expression **)0, expr_none))
		return 0;

	if (!is_data_expression (*expr)) {
		parse_warn ("Expecting a data expression.");
		*lose = 1;
		return 0;
	}
	return 1;
}

/*
 * numeric-expression :== EXTRACT_INT LPAREN data-expression
 *					     COMMA number RPAREN |
 *			  NUMBER
 */

int parse_numeric_expression (expr, cfile, lose)
	struct expression **expr;
	FILE *cfile;
	int *lose;
{
	/* Parse an expression... */
	if (!parse_expression (expr, cfile, lose, context_numeric,
			       (struct expression **)0, expr_none))
		return 0;

	if (!is_numeric_expression (*expr)) {
		parse_warn ("Expecting a numeric expression.");
		*lose = 1;
		return 0;
	}
	return 1;
}

/* Parse a subexpression that does not contain a binary operator. */

int parse_non_binary (expr, cfile, lose, context)
	struct expression **expr;
	FILE *cfile;
	int *lose;
	enum expression_context context;
{
	enum dhcp_token token;
	char *val;
	struct collection *col;
	struct option *option;

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
			return 0;
		}
		for (col = collections; col; col = col -> next)
			if (!strcmp (col -> name, val))
				break;
		if (!col) {
			parse_warn ("unknown collection.");
			*lose = 1;
			return 0;
		}
		if (!expression_allocate (expr, "parse_expression: CHECK"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_check;
		(*expr) -> data.check = col;
		break;

	      case NOT:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: NOT"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_not;
		if (!parse_non_binary (&(*expr) -> data.not,
				       cfile, lose, context)) {
			if (!*lose) {
				parse_warn ("expression expected");
				skip_to_semi (cfile);
			}
			*lose = 1;
			expression_dereference (expr, "parse_expression: NOT");
			return 0;
		}
		break;

	      case EXISTS:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: EXISTS"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_exists;
		(*expr) -> data.option = parse_option_name (cfile, 0);
		if (!(*expr) -> data.option) {
			*lose = 1;
			expression_dereference (expr,
						"parse_expression: EXISTS");
			return 0;
		}
		break;

	      case KNOWN:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: EXISTS"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_known;
		break;

	      case SUBSTRING:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: SUBSTRING"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_substring;

		token = next_token (&val, cfile);
		if (token != LPAREN) {
		      nolparen:
			expression_dereference (expr,
						"parse_expression: nolparen");
			parse_warn ("left parenthesis expected.");
			*lose = 1;
			return 0;
		}

		if (!parse_data_expression (&(*expr) -> data.substring.expr,
					    cfile, lose)) {
		      nodata:
			expression_dereference (expr,
						"parse_expression: nodata");
			parse_warn ("expecting data expression.");
			skip_to_semi (cfile);
			*lose = 1;
			return 0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA) {
		      nocomma:
			expression_dereference (expr,
						"parse_expression: nocomma1");
			parse_warn ("comma expected.");
			*lose = 1;

			return 0;
		}

		if (!parse_numeric_expression
		    (&(*expr) -> data.substring.offset,cfile, lose)) {
		      nonum:
			if (!*lose) {
				parse_warn ("expecting numeric expression.");
				skip_to_semi (cfile);
				*lose = 1;
			}
			expression_dereference (expr,
						"parse_expression: nonum");
			return 0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression
		    (&(*expr) -> data.substring.len, cfile, lose))
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN) {
		      norparen:
			parse_warn ("right parenthesis expected.");
			*lose = 1;
			expression_dereference (expr,
						"parse_expression: norparen");
			return 0;
		}
		break;

	      case SUFFIX:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: SUFFIX"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_suffix;

		token = next_token (&val, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_data_expression (&(*expr) -> data.suffix.expr,
					    cfile, lose))
			goto nodata;

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_data_expression (&(*expr) -> data.suffix.len,
					    cfile, lose))
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN)
			goto norparen;
		break;

	      case OPTION:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: OPTION"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_option;
		(*expr) -> data.option = parse_option_name (cfile, 0);
		if (!(*expr) -> data.option) {
			*lose = 1;
			expression_dereference (expr,
						"parse_expression: OPTION");
			return 0;
		}
		break;

	      case HARDWARE:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: HARDWARE"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_hardware;
		break;

	      case PACKET:
		token = next_token (&val, cfile);
		if (!expression_allocate (expr, "parse_expression: PACKET"))
			log_fatal ("can't allocate expression");
		(*expr) -> op = expr_packet;

		token = next_token (&val, cfile);
		if (token != LPAREN)
			goto nolparen;

		if (!parse_numeric_expression (&(*expr) -> data.packet.offset,
					       cfile, lose))
			goto nonum;

		token = next_token (&val, cfile);
		if (token != COMMA)
			goto nocomma;

		if (!parse_numeric_expression (&(*expr) -> data.packet.len,
					       cfile, lose))
			goto nonum;

		token = next_token (&val, cfile);
		if (token != RPAREN)
			goto norparen;
		break;
		
	      case STRING:
		token = next_token (&val, cfile);
		if (!make_const_data (expr, (unsigned char *)val,
				      strlen (val), 1, 1))
			log_fatal ("can't make constant string expression.");
		break;

	      case EXTRACT_INT:
		token = next_token (&val, cfile);	
		token = next_token (&val, cfile);
		if (token != LPAREN) {
			parse_warn ("left parenthesis expected.");
			*lose = 1;
			return 0;
		}

		if (!expression_allocate (expr,
					  "parse_expression: EXTRACT_INT"))
			log_fatal ("can't allocate expression");

		if (!parse_data_expression (&(*expr) -> data.extract_int,
					    cfile, lose)) {
			parse_warn ("expecting data expression.");
			skip_to_semi (cfile);
			*lose = 1;
			expression_dereference
				(expr, "parse_expression: EXTRACT_INT");
			return 0;
		}

		token = next_token (&val, cfile);
		if (token != COMMA) {
			parse_warn ("comma expected.");
			*lose = 1;
			return 0;
		}

		token = next_token (&val, cfile);
		if (token != NUMBER) {
			parse_warn ("number expected.");
			*lose = 1;
			return 0;
		}
		switch (atoi (val)) {
		      case 8:
			(*expr) -> op = expr_extract_int8;
			break;

		      case 16:
			(*expr) -> op = expr_extract_int16;
			break;

		      case 32:
			(*expr) -> op = expr_extract_int32;
			break;

		      default:
			parse_warn ("unsupported integer size %d", atoi (val));
			*lose = 1;
			skip_to_semi (cfile);
			expression_dereference
				(expr, "parse_expression: EXTRACT_INT");
			return 0;
		}

		token = next_token (&val, cfile);
		if (token != RPAREN) {
			parse_warn ("right parenthesis expected.");
			*lose = 1;
			return 0;
		}
		break;
	
	      case NUMBER:
		if (!expression_allocate (expr,
					  "parse_expression: NUMBER"))
			log_fatal ("can't allocate expression");

		/* If we're in a numeric context, this should just be a
		   number, by itself. */
		if (context == context_numeric) {
			next_token (&val, cfile);	/* Eat the number. */
			(*expr) -> op = expr_const_int;
			(*expr) -> data.const_int = atoi (val);
			break;
		}

	      case NUMBER_OR_NAME:
		(*expr) -> op = expr_const_data;
		if (!parse_cshl (&(*expr) -> data.const_data, cfile)) {
			expression_dereference (expr,
						"parse_expression: cshl");
			return 0;
		}
		break;

		/* Not a valid start to an expression... */
	      default:
		return 0;
	}
	return 1;
}

/* Parse an expression. */

int parse_expression (expr, cfile, lose, context, plhs, binop)
	struct expression **expr;
	FILE *cfile;
	int *lose;
	enum expression_context context;
	struct expression **plhs;
	enum expr_op binop;
{
	enum dhcp_token token;
	char *val;
	struct expression *rhs = (struct expression *)0, *tmp;
	struct expression *lhs;
	enum expr_op next_op;

	/* Consume the left hand side we were passed. */
	if (plhs) {
		lhs = *plhs;
		*plhs = (struct expression *)0;
	} else
		lhs = (struct expression *)0;

      new_rhs:
	if (!parse_non_binary (&rhs, cfile, lose, context)) {
		/* If we already have a left-hand side, then it's not
		   okay for there not to be a right-hand side here, so
		   we need to flag it as an error. */
		if (lhs) {
			if (!*lose) {
				parse_warn ("expecting right-hand side.");
				*lose = 1;
				skip_to_semi (cfile);
			}
			expression_dereference (&lhs, "parse_expression");
		}
		return 0;
	}

	/* At this point, rhs contains either an entire subexpression,
	   or at least a left-hand-side.   If we do not see a binary token
	   as the next token, we're done with the expression. */

	token = peek_token (&val, cfile);
	switch (token) {
	      case EQUAL:
		next_op = expr_equal;
		break;

	      case AND:
		next_op = expr_and;
		break;

	      case OR:
		next_op = expr_or;
		break;

	      default:
		next_op = expr_none;
	}

	/* If we have no lhs yet, we just parsed it. */
	if (!lhs) {
		/* If there was no operator following what we just parsed,
		   then we're done - return it. */
		if (next_op == expr_none) {
			*expr = rhs;
			return 1;
		}
		lhs = rhs;
		rhs = (struct expression *)0;
		binop = next_op;
		next_token (&val, cfile);	/* Consume the operator. */
		goto new_rhs;
	}

	/* Now, if we didn't find a binary operator, we're done parsing
	   this subexpression, so combine it with the preceding binary
	   operator and return the result. */
	if (next_op == expr_none) {
		if (!expression_allocate (expr,
					  "parse_expression: COMBINE"))
			log_fatal ("Can't allocate expression!");

		(*expr) -> op = binop;
		/* All the binary operators' data union members
		   are the same, so we'll cheat and use the member
		   for the equals operator. */
		(*expr) -> data.equal [0] = lhs;
		(*expr) -> data.equal [1] = rhs;
		return 1;
	}

	/* Eat the operator token - we now know it was a binary operator... */
	token = next_token (&val, cfile);

	/* If the binary operator we saw previously has a lower precedence
	   than the next operator, then the rhs we just parsed for that
	   operator is actually the lhs of the operator with the higher
	   precedence - to get the real rhs, we need to recurse on the
	   new operator. */
 	if (binop != expr_none &&
	    op_precedence (binop, next_op) < 0) {
		tmp = rhs;
		rhs = (struct expression *)0;
		if (!parse_expression (&rhs, cfile, lose, op_context (next_op),
				       &tmp, next_op)) {
			if (!*lose) {
				parse_warn ("expecting a subexpression");
				*lose = 1;
			}
			return 0;
		}
		next_op = expr_none;
	}

	/* Now combine the LHS and the RHS using binop. */
	tmp = (struct expression *)0;
	if (!expression_allocate (&tmp, "parse_expression: COMBINE2"))
		log_fatal ("No memory for equal precedence combination.");
	
	/* Store the LHS and RHS. */
	tmp -> data.equal [0] = lhs;
	tmp -> data.equal [1] = rhs;
	tmp -> op = binop;
	
	lhs = tmp;
	tmp = (struct expression *)0;
	rhs = (struct expression *)0;

	/* Recursions don't return until we have parsed the end of the
	   expression, so if we recursed earlier, we can now return what
	   we got. */
	if (next_op == expr_none) {
		*expr = lhs;
		return 1;
	}

	binop = next_op;
	goto new_rhs;
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
	enum dhcp_token token;
	char *fmt;
	struct expression *expr = (struct expression *)0;
	struct expression *tmp;
	int lose;
	struct executable_statement *stmt;
	int ftt = 1;

	token = peek_token (&val, cfile);
	if (token == SEMI) {
		/* Eat the semicolon... */
		token = next_token (&val, cfile);
		goto done;
	}

	/* Parse the option data... */
	do {
		/* Set a flag if this is an array of a simple type (i.e.,
		   not an array of pairs of IP addresses, or something
		   like that. */
		int uniform = option -> format [1] == 'A';

		for (fmt = option -> format; *fmt; fmt++) {
			if (*fmt == 'A')
				break;
			tmp = expr;
			expr = (struct expression *)0;
			if (!parse_option_token (&expr, cfile, fmt,
						 tmp, uniform, lookups)) {
				expression_dereference
					(&tmp, "parse_option_statement");
				return (struct executable_statement *)0;
			}
			if (tmp)
				expression_dereference
					(&tmp, "parse_option_statement");
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

#if 0
	goto done;

      try_expr:
	/* See if there's a data expression, and if so, use it rather than
	   the standard format. */
	expr = parse_data_expression (cfile, &lose);

	/* Found a data expression, but it was bogus? */
	if (lose)
		return (struct executable_statement *)0;
		
#endif /* 0 */
      done:
	if (!parse_semi (cfile))
		return (struct executable_statement *)0;
	stmt = ((struct executable_statement *)
		dmalloc (sizeof *stmt, "parse_option_statement"));
	memset (stmt, 0, sizeof *stmt);
	stmt -> op = op;
	if (expr && !option_cache (&stmt -> data.option,
				   (struct data_string *)0, expr, option))
		log_fatal ("no memory for option cache");
	return stmt;
}

int parse_option_token (rv, cfile, fmt, expr, uniform, lookups)
	struct expression **rv;
	FILE *cfile;
	char *fmt;
	struct expression *expr;
	int uniform;
	int lookups;
{
	char *val;
	enum dhcp_token token;
	struct expression *t = (struct expression *)0;
	unsigned char buf [4];
	int len;
	unsigned char *ob;
	struct iaddr addr;

	switch (*fmt) {
	      case 'U':
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier.");
			skip_to_semi (cfile);
			return 0;
		}
		if (!make_const_data (&t, (unsigned char *)val,
				      strlen (val), 1, 1))
			log_fatal ("No memory for %s", val);
		break;

	      case 'X':
		token = peek_token (&val, cfile);
		if (token == NUMBER_OR_NAME || token == NUMBER) {
			if (!expression_allocate (&t, "parse_option_token"))
				return 0;
			if (!parse_cshl (&t -> data.const_data, cfile))
				return 0;
			t -> op = expr_const_data;
		} else if (token == STRING) {
			token = next_token (&val, cfile);
			if (!make_const_data (&t, (unsigned char *)val,
					      strlen (val), 1, 1))
				log_fatal ("No memory for \"%s\"", val);
		} else {
			parse_warn ("expecting string %s.",
				    "or hexadecimal data");
			skip_to_semi (cfile);
			return 0;
		}
		break;
		
	      case 't': /* Text string... */
		token = next_token (&val, cfile);
		if (token != STRING && !is_identifier (token)) {
			parse_warn ("expecting string.");
			if (token != SEMI)
				skip_to_semi (cfile);
			return 0;
		}
		if (!make_const_data (&t, (unsigned char *)val,
				      strlen (val), 1, 1))
			log_fatal ("No memory for concatenation");
		break;
		
	      case 'I': /* IP address or hostname. */
		if (lookups) {
			if (!parse_ip_addr_or_hostname (&t, cfile, uniform))
				return 0;
		} else {
			if (!parse_ip_addr (cfile, &addr))
				return 0;
			if (!make_const_data (&t, addr.iabuf, addr.len, 0, 1))
				return 0;
		}
		break;
		
	      case 'L': /* Unsigned 32-bit integer... */
	      case 'l':	/* Signed 32-bit integer... */
		token = next_token (&val, cfile);
		if (token != NUMBER) {
		      need_number:
			parse_warn ("expecting number.");
			if (token != SEMI)
				skip_to_semi (cfile);
			return 0;
		}
		convert_num (buf, val, 0, 32);
		if (!make_const_data (&t, buf, 4, 0, 1))
			return 0;
		break;

	      case 's':	/* Signed 16-bit integer. */
	      case 'S':	/* Unsigned 16-bit integer. */
		token = next_token (&val, cfile);
		if (token != NUMBER)
			goto need_number;
		convert_num (buf, val, 0, 16);
		if (!make_const_data (&t, buf, 2, 0, 1))
			return 0;
		break;

	      case 'b':	/* Signed 8-bit integer. */
	      case 'B':	/* Unsigned 8-bit integer. */
		token = next_token (&val, cfile);
		if (token != NUMBER)
			goto need_number;
		convert_num (buf, val, 0, 8);
		if (!make_const_data (&t, buf, 1, 0, 1))
			return 0;
		break;

	      case 'f': /* Boolean flag. */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier.");
		      bad_flag:
			if (token != SEMI)
				skip_to_semi (cfile);
			return 0;
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
		if (!make_const_data (&t, buf, 1, 0, 1))
			return 0;
		break;

	      default:
		log_error ("Bad format %c in parse_option_param.",
		      *fmt);
		skip_to_semi (cfile);
		return 0;
	}
	if (expr) {
		if (!make_concat (rv, expr, t))
			return 0;
		expression_dereference (&t, "parse_option_token");
	} else
		*rv = t;
	return 1;
}

/* allow-deny-keyword :== BOOTP
   			| BOOTING
			| DYNAMIC_BOOTP
			| UNKNOWN_CLIENTS */

int parse_allow_deny (oc, cfile, flag)
	struct option_cache **oc;
	FILE *cfile;
	int flag;
{
	enum dhcp_token token;
	char *val;
	unsigned char rf = flag;
	struct expression *data = (struct expression *)0;
	int status;

	if (!make_const_data (&data, &rf, 1, 0, 1))
		return 0;

	token = next_token (&val, cfile);
	switch (token) {
	      case BOOTP:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_ALLOW_BOOTP]);
		break;

	      case BOOTING:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_ALLOW_BOOTING]);
		break;

	      case DYNAMIC_BOOTP:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_DYNAMIC_BOOTP]);
		break;

	      case UNKNOWN_CLIENTS:
		status = (option_cache
			  (oc, (struct data_string *)0, data,
			   &server_options [SV_BOOT_UNKNOWN_CLIENTS]));
		break;

	      default:
		parse_warn ("expecting allow/deny key");
		skip_to_semi (cfile);
		return 0;
	}
	parse_semi (cfile);
	return status;
}

int parse_auth_key (key_id, cfile)
	struct data_string *key_id;
	FILE *cfile;
{
	struct data_string key_data;
	char *val;
	enum dhcp_token token;
	struct auth_key *key, *old_key = (struct auth_key *)0;

	memset (&key_data, 0, sizeof key_data);

	if (!parse_cshl (key_id, cfile))
		return 0;

	key = auth_key_lookup (key_id);

	token = peek_token (&val, cfile);
	if (token == SEMI) {
		if (!key)
			parse_warn ("reference to undefined key %s",
				    print_hex_1 (key_id -> len,
						 key_id -> data,
						 key_id -> len));
		data_string_forget (key_id, "parse_auth_key");
	} else {
		if (!parse_cshl (&key_data, cfile))
			return 0;
		if (key) {
			parse_warn ("redefinition of key %s",
				    print_hex_1 (key_id -> len,
						 key_id -> data,
						 key_id -> len));
			old_key = key;
		}
		key = new_auth_key (key_data.len, "parse_auth_key");
		if (!key)
			log_fatal ("No memory for key %s",
				   print_hex_1 (key_id -> len,
						key_id -> data,
						key_id -> len));
		key -> length = key_data.len;
		memcpy (key -> data, key_data.data, key_data.len);
		enter_auth_key (key_id, key);
		data_string_forget (&key_data, "parse_auth_key");
	}

	parse_semi (cfile);
	return key_id -> len ? 1 : 0;
}
