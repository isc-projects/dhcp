/* conflex.c

   Lexical scanner for dhcpd config file... */

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
"$Id: conflex.c,v 1.48 1999/07/06 20:41:22 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"
#include <ctype.h>

int lexline;
int lexchar;
char *token_line;
char *prev_line;
char *cur_line;
char *tlname;
int eol_token;

static char line1 [81];
static char line2 [81];
static int lpos;
static int line;
static int tlpos;
static int tline;
static enum dhcp_token token;
static int ugflag;
static char *tval;
static char tokbuf [1500];

#ifdef OLD_LEXER
char comments [4096];
int comment_index;
#endif


static int get_char PROTO ((FILE *));
static enum dhcp_token get_token PROTO ((FILE *));
static void skip_to_eol PROTO ((FILE *));
static enum dhcp_token read_string PROTO ((FILE *));
static enum dhcp_token read_number PROTO ((int, FILE *));
static enum dhcp_token read_num_or_name PROTO ((int, FILE *));
static enum dhcp_token intern PROTO ((char *, enum dhcp_token));

void new_parse (name)
	char *name;
{
	tlname = name;
	lpos = line = 1;
	cur_line = line1;
	prev_line = line2;
	token_line = cur_line;
	cur_line [0] = prev_line [0] = 0;
	warnings_occurred = 0;
}

static int get_char (cfile)
	FILE *cfile;
{
	int c = getc (cfile);
	if (!ugflag) {
		if (c == EOL) {
			if (cur_line == line1) {	
				cur_line = line2;
				prev_line = line1;
			} else {
				cur_line = line1;
				prev_line = line2;
			}
			line++;
			lpos = 1;
			cur_line [0] = 0;
		} else if (c != EOF) {
			if (lpos <= 80) {
				cur_line [lpos - 1] = c;
				cur_line [lpos] = 0;
			}
			lpos++;
		}
	} else
		ugflag = 0;
	return c;		
}

static enum dhcp_token get_token (cfile)
	FILE *cfile;
{
	int c;
	enum dhcp_token ttok;
	static char tb [2];
	int l, p, u;

	do {
		l = line;
		p = lpos;
		u = ugflag;

		c = get_char (cfile);
#ifdef OLD_LEXER
		if (c == '\n' && p == 1 && !u
		    && comment_index < sizeof comments)
			comments [comment_index++] = '\n';
#endif

		if (!(c == '\n' && eol_token) && isascii (c) && isspace (c))
			continue;
		if (c == '#') {
#ifdef OLD_LEXER
			if (comment_index < sizeof comments)
				comments [comment_index++] = '#';
#endif
			skip_to_eol (cfile);
			continue;
		}
		if (c == '"') {
			lexline = l;
			lexchar = p;
			ttok = read_string (cfile);
			break;
		}
		if ((isascii (c) && isdigit (c)) || c == '-') {
			lexline = l;
			lexchar = p;
			ttok = read_number (c, cfile);
			break;
		} else if (isascii (c) && isalpha (c)) {
			lexline = l;
			lexchar = p;
			ttok = read_num_or_name (c, cfile);
			break;
		} else {
			lexline = l;
			lexchar = p;
			tb [0] = c;
			tb [1] = 0;
			tval = tb;
			ttok = c;
			break;
		}
	} while (1);
	return ttok;
}

enum dhcp_token next_token (rval, cfile)
	char **rval;
	FILE *cfile;
{
	int rv;

	if (token) {
		if (lexline != tline)
			token_line = cur_line;
		lexchar = tlpos;
		lexline = tline;
		rv = token;
		token = 0;
	} else {
		rv = get_token (cfile);
		token_line = cur_line;
	}
	if (rval)
		*rval = tval;
#ifdef DEBUG_TOKENS
	fprintf (stderr, "%s:%d ", tval, rv);
#endif
	return rv;
}

enum dhcp_token peek_token (rval, cfile)
	char **rval;
	FILE *cfile;
{
	int x;

	if (!token) {
		tlpos = lexchar;
		tline = lexline;
		token = get_token (cfile);
		if (lexline != tline)
			token_line = prev_line;
		x = lexchar; lexchar = tlpos; tlpos = x;
		x = lexline; lexline = tline; tline = x;
	}
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
#ifdef OLD_LEXER
		if (comment_index < sizeof (comments))
			comments [comment_index++] = c;
#endif
		if (c == EOL) {
			return;
		}
	} while (1);
}

static enum dhcp_token read_string (cfile)
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

static enum dhcp_token read_number (c, cfile)
	int c;
	FILE *cfile;
{
	int seenx = 0;
	int i = 0;
	int token = NUMBER;

	tokbuf [i++] = c;
	for (; i < sizeof tokbuf; i++) {
		c = get_char (cfile);
		if (!seenx && c == 'x') {
			seenx = 1;
#ifndef OLD_LEXER
		} else if (isascii (c) && !isxdigit (c) &&
			   (c == '-' || c == '_' || isalpha (c))) {
			token = NAME;
		} else if (isascii (c) && !isdigit (c) && isxdigit (c)) {
			token = NUMBER_OR_NAME;
#endif
		} else if (!isascii (c) || !isxdigit (c)) {
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
	return token;
}

static enum dhcp_token read_num_or_name (c, cfile)
	int c;
	FILE *cfile;
{
	int i = 0;
	enum dhcp_token rv = NUMBER_OR_NAME;
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
			rv = NAME;
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

static enum dhcp_token intern (atom, dfv)
	char *atom;
	enum dhcp_token dfv;
{
	if (!isascii (atom [0]))
		return dfv;

	switch (tolower (atom [0])) {
	      case 'a':
		if (!strncasecmp (atom + 1, "uth", 3)) {
			if (!strncasecmp (atom + 3, "uthenticat", 10)) {
				if (!strcasecmp (atom + 13, "ed"))
					return AUTHENTICATED;
				if (!strcasecmp (atom + 13, "ion"))
					return AUTHENTICATION;
				break;
			}
			if (!strcasecmp (atom + 1, "uthoritative"))
				return AUTHORITATIVE;
			if (!strcasecmp (atom + 1, "uth-key"))
				return AUTH_KEY;
			break;
		}
		if (!strcasecmp (atom + 1, "nd"))
			return AND;
		if (!strcasecmp (atom + 1, "ppend"))
			return APPEND;
		if (!strcasecmp (atom + 1, "llow"))
			return ALLOW;
		if (!strcasecmp (atom + 1, "lias"))
			return ALIAS;
		if (!strcasecmp (atom + 1, "bandoned"))
			return ABANDONED;
		if (!strcasecmp (atom + 1, "dd"))
			return TOKEN_ADD;
		if (!strcasecmp (atom + 1, "ll"))
			return ALL;
		if (!strcasecmp (atom + 1, "rray"))
			return ARRAY;
		break;
	      case 'b':
		if (!strcasecmp (atom + 1, "inary-to-ascii"))
			return BINARY_TO_ASCII;
		if (!strcasecmp (atom + 1, "ackoff-cutoff"))
			return BACKOFF_CUTOFF;
		if (!strcasecmp (atom + 1, "ootp"))
			return BOOTP;
		if (!strcasecmp (atom + 1, "ooting"))
			return BOOTING;
		if (!strcasecmp (atom + 1, "oot-unknown-clients"))
			return BOOT_UNKNOWN_CLIENTS;
		if (!strcasecmp (atom + 1, "reak"))
			return BREAK;
		if (!strcasecmp (atom + 1, "illing"))
			return BILLING;
		if (!strcasecmp (atom + 1, "oolean"))
			return BOOLEAN;
		break;
	      case 'c':
		if (!strcasecmp (atom + 1, "ode"))
			return CODE;
		if (!strcasecmp (atom + 1, "heck"))
			return CHECK;
		if (!strcasecmp (atom + 1, "lass"))
			return CLASS;
		if (!strcasecmp (atom + 1, "iaddr"))
			return CIADDR;
		if (!strncasecmp (atom + 1, "lient", 5)) {
			if (!strcasecmp (atom + 6, "-identifier"))
				return CLIENT_IDENTIFIER;
			if (!strcasecmp (atom + 6, "-hostname"))
				return CLIENT_HOSTNAME;
			if (!strcasecmp (atom + 6, "s"))
				return CLIENTS;
		}
		if (!strncasecmp (atom + 1, "oncat", 5))
			return CONCAT;
		if (!strcasecmp (atom + 1, "ommunications-interrupted"))
			return COMMUNICATIONS_INTERRUPTED;
		break;
	      case 'd':
		if (!strcasecmp (atom + 1, "dns-fwd-name"))
			return DDNS_FWD_NAME;
		if (!strcasecmp (atom + 1, "dns-rev-name"))
			return DDNS_REV_NAME;
		if (!strcasecmp (atom + 1, "omain"))
			return DOMAIN;
		if (!strcasecmp (atom + 1, "eny"))
			return DENY;
		if (!strncasecmp (atom + 1, "efault", 6)) {
			if (!atom [7])
				return DEFAULT;
			if (!strcasecmp (atom + 7, "-lease-time"))
				return DEFAULT_LEASE_TIME;
			break;
		}
		if (!strncasecmp (atom + 1, "ynamic", 6)) {
			if (!atom [7])
				return DYNAMIC;
			if (!strncasecmp (atom + 7, "-bootp", 6)) {
				if (!atom [13])
					return DYNAMIC_BOOTP;
				if (!strcasecmp (atom + 13, "-lease-cutoff"))
					return DYNAMIC_BOOTP_LEASE_CUTOFF;
				if (!strcasecmp (atom + 13, "-lease-length"))
					return DYNAMIC_BOOTP_LEASE_LENGTH;
				break;
			}
		}
		break;
	      case 'e':
		if (isascii (atom [1]) && tolower (atom [1]) == 'x') {
			if (!strcasecmp (atom + 2, "tract-int"))
				return EXTRACT_INT;
			if (!strcasecmp (atom + 2, "ncode-int"))
				return ENCODE_INT;
			if (!strcasecmp (atom + 2, "ists"))
				return EXISTS;
		}
		if (!strcasecmp (atom + 1, "thernet"))
			return ETHERNET;
		if (!strcasecmp (atom + 1, "nds"))
			return ENDS;
		if (!strcasecmp (atom + 1, "xpire"))
			return EXPIRE;
		if (!strncasecmp (atom + 1, "ls", 2)) {
			if (!strcasecmp (atom + 3, "e"))
				return ELSE;
			if (!strcasecmp (atom + 3, "if"))
				return ELSIF;
			break;
		}
		break;
	      case 'f':
		if (!strcasecmp (atom + 1, "ilename"))
			return FILENAME;
		if (!strcasecmp (atom + 1, "ixed-address"))
			return FIXED_ADDR;
		if (!strcasecmp (atom + 1, "ddi"))
			return FDDI;
		break;
	      case 'g':
		if (!strcasecmp (atom + 1, "iaddr"))
			return GIADDR;
		if (!strcasecmp (atom + 1, "roup"))
			return GROUP;
		if (!strcasecmp (atom + 1, "et-lease-hostnames"))
			return GET_LEASE_HOSTNAMES;
		break;
	      case 'h':
		if (!strcasecmp (atom + 1, "ost"))
			return HOST;
		if (!strcasecmp (atom + 1, "ardware"))
			return HARDWARE;
		if (!strcasecmp (atom + 1, "ostname"))
			return HOSTNAME;
		break;
	      case 'i':
		if (!strcasecmp (atom + 1, "nteger"))
			return INTEGER;
		if (!strcasecmp (atom + 1, "p-address"))
			return IP_ADDRESS;
		if (!strcasecmp (atom + 1, "nitial-interval"))
			return INITIAL_INTERVAL;
		if (!strcasecmp (atom + 1, "nterface"))
			return INTERFACE;
		if (!strcasecmp (atom + 1, "dentifier"))
			return IDENTIFIER;
		if (!strcasecmp (atom + 1, "f"))
			return IF;
		break;
	      case 'k':
		if (!strcasecmp (atom + 1, "nown"))
			return KNOWN;
		break;
	      case 'l':
		if (!strcasecmp (atom + 1, "ease"))
			return LEASE;
		if (!strcasecmp (atom + 1, "eased-address"))
			return LEASED_ADDRESS;
		if (!strcasecmp (atom + 1, "imit"))
			return LIMIT;
		break;
	      case 'm':
		if (!strncasecmp (atom + 1, "ax-", 3)) {
			if (!strcasecmp (atom + 4, "lease-time"))
				return MAX_LEASE_TIME;
			if (!strcasecmp (atom + 4, "transmit-idle"))
				return MAX_TRANSMIT_IDLE;
			if (!strcasecmp (atom + 4, "response-delay"))
				return MAX_RESPONSE_DELAY;
		}
		if (!strncasecmp (atom + 1, "in-", 3)) {
			if (!strcasecmp (atom + 4, "lease-time"))
				return MIN_LEASE_TIME;
			if (!strcasecmp (atom + 4, "secs"))
				return MIN_SECS;
			break;
		}
		if (!strncasecmp (atom + 1, "edi", 3)) {
			if (!strcasecmp (atom + 4, "a"))
				return MEDIA;
			if (!strcasecmp (atom + 4, "um"))
				return MEDIUM;
			break;
		}
		if (!strcasecmp (atom + 1, "atch"))
			return MATCH;
		if (!strcasecmp (atom + 1, "embers"))
			return MEMBERS;
		if (!strcasecmp (atom + 1, "y"))
			return MY;
		break;
	      case 'n':
		if (!strcasecmp (atom + 1, "ormal"))
			return NORMAL;
		if (!strcasecmp (atom + 1, "ameserver"))
			return NAMESERVER;
		if (!strcasecmp (atom + 1, "etmask"))
			return NETMASK;
		if (!strcasecmp (atom + 1, "ext-server"))
			return NEXT_SERVER;
		if (!strcasecmp (atom + 1, "ot"))
			return TOKEN_NOT;
		break;
	      case 'o':
		if (!strcasecmp (atom + 1, "r"))
			return OR;
		if (!strcasecmp (atom + 1, "ption"))
			return OPTION;
		if (!strcasecmp (atom + 1, "ne-lease-per-client"))
			return ONE_LEASE_PER_CLIENT;
		if (!strcasecmp (atom + 1, "f"))
			return OF;
		break;
	      case 'p':
		if (!strcasecmp (atom + 1, "repend"))
			return PREPEND;
		if (!strcasecmp (atom + 1, "acket"))
			return PACKET;
		if (!strcasecmp (atom + 1, "ool"))
			return POOL;
		if (!strcasecmp (atom + 1, "seudo"))
			return PSEUDO;
		if (!strcasecmp (atom + 1, "eer"))
			return PEER;
		if (!strcasecmp (atom + 1, "rimary"))
			return PRIMARY;
		if (!strncasecmp (atom + 1, "artner", 6)) {
			if (!atom [7])
				return PARTNER;
			if (!strcasecmp (atom + 7, "-down"))
				return PARTNER_DOWN;
		}
		if (!strcasecmp (atom + 1, "ort"))
			return PORT;
		if (!strcasecmp (atom + 1, "otential-conflict"))
			return POTENTIAL_CONFLICT;
		break;
	      case 'r':
		if (!strcasecmp (atom + 1, "ange"))
			return RANGE;
		if (!strcasecmp (atom + 1, "ecover"))
			return RECOVER;
		if (!strcasecmp (atom + 1, "equest"))
			return REQUEST;
		if (!strcasecmp (atom + 1, "equire"))
			return REQUIRE;
		if (!strcasecmp (atom + 1, "equire"))
			return REQUIRE;
		if (!strcasecmp (atom + 1, "etry"))
			return RETRY;
		if (!strcasecmp (atom + 1, "enew"))
			return RENEW;
		if (!strcasecmp (atom + 1, "ebind"))
			return REBIND;
		if (!strcasecmp (atom + 1, "eboot"))
			return REBOOT;
		if (!strcasecmp (atom + 1, "eject"))
			return REJECT;
		if (!strcasecmp (atom + 1, "everse"))
			return REVERSE;
		break;
	      case 's':
		if (!strcasecmp (atom + 1, "igned"))
			return SIGNED;
		if (!strcasecmp (atom + 1, "tring"))
			return STRING;
		if (!strcasecmp (atom + 1, "uffix"))
			return SUFFIX;
		if (!strcasecmp (atom + 1, "earch"))
			return SEARCH;
		if (!strcasecmp (atom + 1, "tarts"))
			return STARTS;
		if (!strcasecmp (atom + 1, "iaddr"))
			return SIADDR;
		if (!strcasecmp (atom + 1, "hared-network"))
			return SHARED_NETWORK;
		if (!strcasecmp (atom + 1, "econdary"))
			return SECONDARY;
		if (!strcasecmp (atom + 1, "erver-name"))
			return SERVER_NAME;
		if (!strcasecmp (atom + 1, "erver-identifier"))
			return SERVER_IDENTIFIER;
		if (!strcasecmp (atom + 1, "elect-timeout"))
			return SELECT_TIMEOUT;
		if (!strcasecmp (atom + 1, "end"))
			return SEND;
		if (!strcasecmp (atom + 1, "cript"))
			return SCRIPT;
		if (!strcasecmp (atom + 1, "upersede"))
			return SUPERSEDE;
		if (!strncasecmp (atom + 1, "ub", 2)) {
			if (!strcasecmp (atom + 3, "string"))
				return SUBSTRING;
			if (!strcasecmp (atom + 3, "net"))
				return SUBNET;
			if (!strcasecmp (atom + 3, "class"))
				return SUBCLASS;
			break;
		}
		if (!strcasecmp (atom + 1, "pawn"))
			return SPAWN;
		if (!strcasecmp (atom + 1, "pace"))
			return SPACE;
		break;
	      case 't':
		if (!strcasecmp (atom + 1, "imestamp"))
			return TIMESTAMP;
		if (!strcasecmp (atom + 1, "imeout"))
			return TIMEOUT;
		if (!strcasecmp (atom + 1, "oken-ring"))
			return TOKEN_RING;
		if (!strcasecmp (atom + 1, "ext"))
			return TEXT;
		break;
	      case 'u':
		if (!strcasecmp (atom + 1, "nsigned"))
			return UNSIGNED;
		if (!strcasecmp (atom + 1, "id"))
			return UID;
		if (!strncasecmp (atom + 1, "se", 2)) {
			if (!strcasecmp (atom + 3, "r-class"))
				return USER_CLASS;
			if (!strcasecmp (atom + 3, "-host-decl-names"))
				return USE_HOST_DECL_NAMES;
			if (!strcasecmp (atom + 3,
					 "-lease-addr-for-default-route"))
				return USE_LEASE_ADDR_FOR_DEFAULT_ROUTE;
			break;
		}
		if (!strncasecmp (atom + 1, "nknown", 6)) {
			if (!strcasecmp (atom + 7, "-clients"))
				return UNKNOWN_CLIENTS;
			if (!atom [7])
				return UNKNOWN;
			break;
		}
		if (!strcasecmp (atom + 1, "nauthenticated"))
			return AUTHENTICATED;
		break;
	      case 'v':
		if (!strcasecmp (atom + 1, "endor-class"))
			return VENDOR_CLASS;
		break;
	      case 'w':
		if (!strcasecmp (atom + 1, "ith"))
			return WITH;
		break;
	      case 'y':
		if (!strcasecmp (atom + 1, "iaddr"))
			return YIADDR;
		break;
	}
	return dfv;
}
