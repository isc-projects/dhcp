/* dhctoken.h

   Tokens for config file lexer and parser. */

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

enum dhcp_token {
	SEMI = ';',
	DOT = '.',
	COLON = ':',
	COMMA = ',',
	SLASH = '/',
	LBRACE = '{',
	RBRACE = '}',
	LPAREN = '(',
	RPAREN = ')',
	EQUAL = '=',

	HOST = 256,
	FIRST_TOKEN = HOST,
	HARDWARE = 257,
	FILENAME = 258,
	FIXED_ADDR = 259,
	OPTION = 260,
	ETHERNET = 261,
	STRING = 262,
	NUMBER = 263,
	NUMBER_OR_NAME = 264,
	NAME = 265,
	TIMESTAMP = 266,
	STARTS = 267,
	ENDS = 268,
	UID = 269,
	CLASS = 270,
	LEASE = 271,
	RANGE = 272,
	PACKET = 273,
	CIADDR = 274,
	YIADDR = 275,
	SIADDR = 276,
	GIADDR = 277,
	SUBNET = 278,
	NETMASK = 279,
	DEFAULT_LEASE_TIME = 280,
	MAX_LEASE_TIME = 281,
	VENDOR_CLASS = 282,
	USER_CLASS = 283,
	SHARED_NETWORK = 284,
	SERVER_NAME = 285,
	DYNAMIC_BOOTP = 286,
	SERVER_IDENTIFIER = 287,
	DYNAMIC_BOOTP_LEASE_CUTOFF = 288,
	DYNAMIC_BOOTP_LEASE_LENGTH = 289,
	BOOT_UNKNOWN_CLIENTS = 290,
	NEXT_SERVER = 291,
	TOKEN_RING = 292,
	GROUP = 293,
	ONE_LEASE_PER_CLIENT = 294,
	GET_LEASE_HOSTNAMES = 295,
	USE_HOST_DECL_NAMES = 296,
	SEND = 297,
	CLIENT_IDENTIFIER = 298,
	REQUEST = 299,
	REQUIRE = 300,
	TIMEOUT = 301,
	RETRY = 302,
	SELECT_TIMEOUT = 303,
	SCRIPT = 304,
	INTERFACE = 305,
	RENEW = 306,
	REBIND = 307,
	EXPIRE = 308,
	UNKNOWN_CLIENTS = 309,
	ALLOW = 310,
	BOOTP = 311,
	DENY = 312,
	BOOTING = 313,
	DEFAULT = 314,
	MEDIA = 315,
	MEDIUM = 316,
	ALIAS = 317,
	REBOOT = 318,
	ABANDONED = 319,
	BACKOFF_CUTOFF = 320,
	INITIAL_INTERVAL = 321,
	NAMESERVER = 322,
	DOMAIN = 323,
	SEARCH = 324,
	SUPERSEDE = 325,
	APPEND = 326,
	PREPEND = 327,
	HOSTNAME = 328,
	CLIENT_HOSTNAME = 329,
	REJECT = 330,
	USE_LEASE_ADDR_FOR_DEFAULT_ROUTE = 331,
	MIN_LEASE_TIME = 332,
	MIN_SECS = 333,
	AND = 334,
	OR = 335,
	NOT = 336,
	SUBSTRING = 337,
	SUFFIX = 338,
	CHECK = 339,
	EXTRACT_INT = 340,
	IF = 341,
	ADD = 342,
	BREAK = 343,
	ELSE = 344,
	ELSIF = 345,
	SUBCLASS = 346,
	MATCH = 347,
	SPAWN = 348,
	WITH = 349,
	EXISTS = 350,
};

#define is_identifier(x)	((x) >= FIRST_TOKEN &&	\
				 (x) != STRING &&	\
				 (x) != NUMBER &&	\
				 (x) != EOF)
