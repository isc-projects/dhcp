/* conflex.c

   Lexical scanner for dhcpd config file... */

/*
 * Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.
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
#include "dhctoken.h"
#include <ctype.h>

static int line;
static int lpos;
int tlpos;
int tline;
static int token;
static int ugflag;
static char *tval;
static char tokbuf [1500];

static int get_char PROTO ((FILE *));
static int get_token PROTO ((FILE *));
static void skip_to_eol PROTO ((FILE *));
static int read_string PROTO ((FILE *));
static int read_number PROTO ((int, FILE *));
static int read_num_or_atom PROTO ((int, FILE *));
static int intern PROTO ((char *, int));

static int get_char (cfile)
	FILE *cfile;
{
	char c = getc (cfile);
	if (!ugflag) {
		if (c == EOL) {
			line++;
			lpos = 1;
		} else {
			lpos++;
		}
	} else
		ugflag = 0;
	return c;		
}

static int get_token (cfile)
	FILE *cfile;
{
	int c;
	int i;
	int ttok;
#ifdef DEBUG_TOKENS
	static char tb [2];
#endif

	do {
		c = get_char (cfile);
		if (isascii (c) && isspace (c))
			continue;
		if (c == '#') {
			skip_to_eol (cfile);
			continue;
		}
		tlpos = lpos;
		tline = line;
		if (c == '"') {
			ttok = read_string (cfile);
			break;
		}
		if (isascii (c) && isdigit (c)) {
			ttok = read_number (c, cfile);
			break;
		} else if (isascii (c) && isalpha (c)) {
			ttok = read_num_or_atom (c, cfile);
			break;
		} else {
#ifdef DEBUG_TOKENS
			tb [0] = c;
			tb [1] = 0;
			tval = tb;
#else
			tval = 0;
#endif
			ttok = c;
			break;
		}
	} while (1);
	return ttok;
}

int next_token (rval, cfile)
	char **rval;
	FILE *cfile;
{
	int rv;

	if (token) {
		rv = token;
		token = 0;
	} else {
		rv = get_token (cfile);
	}
	if (rval)
		*rval = tval;
#ifdef DEBUG_TOKENS
	fprintf (stderr, "%s:%d ", tval, rv);
#endif
	return rv;
}

int peek_token (rval, cfile)
	char **rval;
	FILE *cfile;
{
	if (!token)
		token = get_token (cfile);
	if (rval)
		*rval = tval;
#ifdef DEBUG_TOKENS
	fprintf (stderr, "(%s:%d) ", tval, token);
#endif
	return token;
}

static void skip_to_eol (cfile)
	FILE *cfile;
{
	int c;
	do {
		c = get_char (cfile);
		if (c == EOF)
			return;
		if (c == EOL) {
			ungetc (c, cfile);
			ugflag = 1;
			return;
		}
	} while (1);
}

static int read_string (cfile)
	FILE *cfile;
{
	int i;
	int bs = 0;
	int c;

	for (i = 0; i < sizeof tokbuf; i++) {
		c = get_char (cfile);
		if (c == EOF) {
			parse_warn ("eof in string constant");
			break;
		}
		if (bs) {
			bs = 0;
			tokbuf [i] = c;
		} else if (c == '\\')
			bs = 1;
		else if (c == '"')
			break;
		else
			tokbuf [i] = c;
	}
	/* Normally, I'd feel guilty about this, but we're talking about
	   strings that'll fit in a DHCP packet here... */
	if (i == sizeof tokbuf) {
		parse_warn ("string constant larger than internal buffer");
		--i;
	}
	tokbuf [i] = 0;
	tval = tokbuf;
	return STRING;
}

static int read_number (c, cfile)
	int c;
	FILE *cfile;
{
	int seenx = 0;
	int i = 0;
	tokbuf [i++] = c;
	for (; i < sizeof tokbuf; i++) {
		c = get_char (cfile);
		if (!seenx && c == 'x')
			seenx = 1;
		else if (!isascii (c) || !isxdigit (c)) {
			ungetc (c, cfile);
			ugflag = 1;
			break;
		}
		tokbuf [i] = c;
	}
	if (i == sizeof tokbuf) {
		parse_warn ("numeric token larger than internal buffer");
		--i;
	}
	tokbuf [i] = 0;
	tval = tokbuf;
	return NUMBER;
}

static int read_num_or_atom (c, cfile)
	int c;
	FILE *cfile;
{
	int i = 0;
	int rv = NUMBER_OR_ATOM;
	tokbuf [i++] = c;
	for (; i < sizeof tokbuf; i++) {
		c = get_char (cfile);
		if (!isascii (c) ||
		    (c != '-' && c != '_' && !isalnum (c))) {
			ungetc (c, cfile);
			ugflag = 1;
			break;
		}
		if (!isxdigit (c))
			rv = ATOM;
		tokbuf [i] = c;
	}
	if (i == sizeof tokbuf) {
		parse_warn ("token larger than internal buffer");
		--i;
	}
	tokbuf [i] = 0;
	tval = tokbuf;
	return intern (tval, rv);
}

static int intern (atom, dfv)
	char *atom;
	int dfv;
{
	switch (atom [0]) {
	      case 'c':
		if (!strcasecmp (atom + 1, "lass"))
			return CLASS;
		break;
	      case 'e':
		if (!strcasecmp (atom + 1, "thernet"))
			return ETHERNET;
		if (!strcasecmp (atom + 1, "nds"))
			return ENDS;
		break;
	      case 'f':
		if (!strcasecmp (atom + 1, "ilename"))
			return FILENAME;
		if (!strcasecmp (atom + 1, "ixed-address"))
			return FIXED_ADDR;
		break;
	      case 'h':
		if (!strcasecmp (atom + 1, "ost"))
			return HOST;
		if (!strcasecmp (atom + 1, "ardware"))
			return HARDWARE;
		break;
	      case 'l':
		if (!strcasecmp (atom + 1, "ease"))
			return LEASE;
		break;
	      case 'o':
		if (!strcasecmp (atom + 1, "ption"))
			return OPTION;
		break;
	      case 'r':
		if (!strcasecmp (atom + 1, "ange"))
			return RANGE;
		break;
	      case 's':
		if (!strcasecmp (atom + 1, "tarts"))
			return STARTS;
		break;
	      case 't':
		if (!strcasecmp (atom + 1, "timestamp"))
			return TIMESTAMP;
		break;
	      case 'u':
		if (!strcasecmp (atom + 1, "id"))
			return UID;
		break;
	}
	return dfv;
}
