/* options.c

   DHCP options parsing and reassembly. */

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

#define DHCP_OPTION_DATA
#include "dhcpd.h"

/* Parse all available options out of the specified packet. */

void parse_options (packet)
	struct packet *packet;
{
	/* Initially, zero all option pointers. */
	memset (packet -> options, 0, sizeof (packet -> options));

	/* If we don't see the magic cookie, there's nothing to parse. */
	if (memcmp (packet -> raw -> options, DHCP_OPTIONS_COOKIE, 4)) {
		packet -> options_valid = 0;
		return;
	}

	/* Go through the options field, up to the end of the packet
	   or the End field. */
	parse_option_buffer (packet, &packet -> raw -> options [4],
			     packet -> packet_length - DHCP_FIXED_LEN);
	/* If we parsed a DHCP Option Overload option, parse more
	   options out of the buffer(s) containing them. */
	if (packet -> options_valid
	    && packet -> options [DHO_DHCP_OPTION_OVERLOAD].data) {
		if (packet -> options [DHO_DHCP_OPTION_OVERLOAD].data [0] & 1)
			parse_option_buffer (packet,
					     packet -> raw -> file,
					     sizeof packet -> raw -> file);
		if (packet -> options [DHO_DHCP_OPTION_OVERLOAD].data [0] & 2)
			parse_option_buffer (packet,
					     packet -> raw -> sname,
					     sizeof packet -> raw -> sname);
	}
}

/* Parse options out of the specified buffer, storing addresses of option
   values in packet -> options and setting packet -> options_valid if no
   errors are encountered. */

void parse_option_buffer (packet, buffer, length)
	struct packet *packet;
	unsigned char *buffer;
	int length;
{
	unsigned char *s, *t;
	unsigned char *end = buffer + length;
	int len;
	int code;

	for (s = buffer; *s != DHO_END && s < end; ) {
		code = s [0];
		/* Pad options don't have a length - just skip them. */
		if (code == DHO_PAD) {
			++s;
			continue;
		}
		/* All other fields (except end, see above) have a
		   one-byte length. */
		len = s [1];
		/* If the length is outrageous, the options are bad. */
		if (s + len + 2 > end) {
			warn ("Option %s length %d overflows input buffer.",
			      dhcp_options [code].name,
			      len);
			packet -> options_valid = 0;
			return;
		}
		/* If we haven't seen this option before, just make
		   space for it and copy it there. */
		if (!packet -> options [code].data) {
			if (!(t = (unsigned char *)malloc (len + 1)))
				error ("Can't allocate storage for option %s.",
				       dhcp_options [code].name);
			/* Copy and NUL-terminate the option (in case it's an
			   ASCII string. */
			memcpy (t, &s [2], len);
			t [len] = 0;
			packet -> options [code].len = len;
			packet -> options [code].data = t;
		} else {
			/* If it's a repeat, concatenate it to whatever
			   we last saw.   This is really only required
			   for clients, but what the heck... */
			t = (unsigned char *)
				malloc (len + packet -> options [code].len);
			if (!t)
				error ("Can't expand storage for option %s.",
				       dhcp_options [code].name);
			memcpy (t, packet -> options [code].data,
				packet -> options [code].len);
			memcpy (t + packet -> options [code].len,
				&s [2], len);
			packet -> options [code].len += len;
			t [packet -> options [code].len] = 0;
			free (packet -> options [code].data);
			packet -> options [code].data = t;
		}
		s += len + 2;
	}
	packet -> options_valid = 1;
}

/* Cons up options based on client-supplied desired option list (if any)
   and selected server option list. */

void cons_options (inpacket, outpacket, options, overload)
	struct packet *inpacket;
	struct packet *outpacket;
	struct tree_cache **options;
	int overload;	/* Overload flags that may be set. */
{
	option_mask options_have;	/* Options we can send. */
	option_mask options_want;	/* Options client wants. */
	option_mask options_done;	/* Options we've already encoded. */
	option_mask temp;		/* Working option mask. */
	unsigned char *priority_list;
	int priority_len;
	unsigned char *buffer = outpacket -> raw -> options;
	int buflen, bufix = 0;
	int reserved = 3;		/* Reserved space for overload. */
	unsigned char *overload_ptr = (unsigned char *)0;
	int stored_length [256];
	int missed = 0;
	int missed_code = 0;
	int missed_length = 0;
	int result;
	int i;

	/* If there's no place to overload with options, don't save space
	   for an overload option. */
	if (!overload)
		reserved = 0;

	/* Zero out the stored-lengths array. */
	memset (stored_length, 0, sizeof stored_length);

	/* If the client has provided a maximum DHCP message size,
	   use that.   Otherwise, we use the default MTU size (576 bytes). */
	/* XXX Maybe it would be safe to assume that we can send a packet
	   to the client that's as big as the one it sent us, even if it
	   didn't specify a large MTU. */
	if (inpacket && inpacket -> options [DHO_DHCP_MAX_MESSAGE_SIZE].data)
		buflen = (getUShort (inpacket -> options
				     [DHO_DHCP_MAX_MESSAGE_SIZE].data)
			  - DHCP_FIXED_LEN);
	else
		buflen = 576 - DHCP_FIXED_LEN;

	/* If the client has provided a list of options that it wishes
	   returned, use it to prioritize. */
	/* XXX Some options are *required*, and client may not ask for
	   them. */
	if (inpacket &&
	    inpacket -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].data) {
		priority_list =
			inpacket -> options
				[DHO_DHCP_PARAMETER_REQUEST_LIST].data;
		priority_len =
			inpacket -> options
				[DHO_DHCP_PARAMETER_REQUEST_LIST].len;
	} else {
	/* Otherwise, prioritize based on the default priority list. */
		priority_list = dhcp_option_default_priority_list;
		priority_len = sizeof_dhcp_option_default_priority_list;
	}

	/* Make a bitmask of all the options the client wants. */
	OPTION_ZERO (options_want);
	for (i = 0; i < priority_len; i++)
		OPTION_SET (options_want, priority_list [i]);

	/* Make a bitmask of all the options we have available. */
	OPTION_ZERO (options_have);
	for (i = 0; i < 256; i++)
		if (options [i])
			OPTION_SET (options_have, i);
	
	/* Put the cookie up front... */
	memcpy (buffer, DHCP_OPTIONS_COOKIE, 4);
	bufix += 4;

      again:
	/* Try copying out options that fit easily. */
	for (i = 0; i < priority_len; i++) {
		/* Code for next option to try to store. */
		int code = priority_list [i];

		/* Number of bytes left to store (some may already
		   have been stored by a previous pass). */
		int length;

		/* If no data is available for this option, skip it. */
		if (!options [code])
			continue;

		/* Don't look at options that have already been stored. */
		if (stored_length [code] ==
		    options [code] -> len) {
			continue;
		}

		/* Find the value of the option... */
		if (!tree_evaluate (options [code])) {
			continue;
		}

		/* We should now have a constant length for the option. */
		length = (options [code] -> len - stored_length [code]);

		/* If there's no space for this option, skip it. */
		if ((bufix + OPTION_SPACE (length) + reserved) > buflen) {
			/* If this is the first missed option, remember it. */
			if (++missed == 1) {
				missed_code = code;
				missed_length = length;
			}
			continue;
		}
		
		/* Otherwise, store the option. */
		result = store_option (options, code,
				       buffer + bufix,
				       buflen - bufix - reserved,
				       stored_length);
		bufix += result;

		/* The following test should always succeed because of
		   preconditioning above. */
		if (stored_length [code] == options [code] -> len)
			OPTION_SET (options_done, code);
		else {
			warn ("%s: Only stored %d out of %d bytes.",
			      dhcp_options [code].name,
			      stored_length [code],
			      options [code] -> len);
			if (++missed == 1) {
				missed_code = code;
				missed_length = options [code] -> len
					- stored_length [code];
			}
		}
	}

	if (buffer == outpacket -> raw -> options) {
		outpacket -> packet_length = DHCP_FIXED_LEN + bufix;
	}

	/* If we didn't miss any options, we're done. */
	/* XXX Maybe we want to try to encode options the client didn't
	   request but that we have available? */
	if (!missed) {
		/* If there's space, store an End option code. */
		if (bufix < buflen)
			buffer [bufix++] = DHO_END;
		/* If there's still space, pad it. */
		while (bufix < buflen)
			buffer [bufix++] = DHO_PAD;
		return;
	}

	/* If we did miss one or more options, they must not have fit.
	   It's possible, though, that there's only one option left to
	   store, and that it would fit if we weren't reserving space
	   for the overload option.   In that case, we want to avoid
	   overloading. */
	if (reserved && missed == 1
	    && (bufix + OPTION_SPACE (missed_length) <= buflen)) {
		result = store_option (options, missed_code,
				       buffer + bufix, buflen - bufix,
				       stored_length);
		bufix += result;
		/* This test should always fail -- we'll send bad
		   data if it doesn't. */
		if (stored_length [missed_code]
		    == options [missed_code] -> len) {
			OPTION_SET (options_done, missed_code);
		} else {
			warn ("%s (last): Only stored %d out of %d bytes.",
			      dhcp_options [missed_code].name,
			      stored_length [missed_code],
			      options [missed_code] -> len);
		}
		return;
	}

	/* We've crammed in all the options that completely fit in
	   the current buffer, but maybe we can fit part of the next
	   option into the current buffer and part into the next. */
	if (bufix + OPTION_SPACE (missed_length) + reserved
	    < buflen + (overload & 1 ? 128 : 0) + (overload & 2 ? 64 : 0)) {
		result = store_option (options, missed_code,
				       buffer + bufix,
				       buflen - bufix - reserved,
				       stored_length);
		bufix += result;

		/* This test should never fail. */
		if (stored_length [missed_code]
		    == options [missed_code] -> len) {
			OPTION_SET (options_done, missed_code);
			warn ("%s: Unexpected completed store.",
			      dhcp_options [missed_code].name);
		}
	}

	/* Okay, nothing else is going to fit in the current buffer
	   except possibly the override option.   Store that. */
	if (reserved) {
		buffer [bufix++] = DHO_DHCP_OPTION_OVERLOAD;
		buffer [bufix++] = 1;
		overload_ptr = buffer + bufix;
		buffer [bufix++] = 0;
		/* If there's space, store an End option code. */
		if (bufix < buflen)
			buffer [bufix++] = DHO_END;
		/* If there's still space, pad it. */
		while (bufix < buflen)
			buffer [bufix++] = DHO_PAD;
	}
	    
	/* If we've fallen through to here, we still have options to
	   store, and may be able to overload options into the file
	   and server name fields of the DHCP packet. */

	/* We should have stored an overload option by now if we're
	   going to need it, so if this test fails, there's a programming
	   error somewhere above. */
	if (overload && !overload_ptr) {
		warn ("Need to overload, but didn't store overload option!");
		return;
	}

	/* Can we use the file buffer? */
	if (overload & 1) {
		buffer = outpacket -> raw -> file;
		buflen = sizeof outpacket -> raw -> file;
		bufix = 0;
		overload &= ~1;
		goto again;
	}
	/* Can we use the sname buffer? */
	if (overload & 2) {
		buffer = outpacket -> raw -> sname;
		buflen = sizeof outpacket -> raw -> sname;
		bufix = 0;
		overload &= ~2;
		goto again;
	}

	warn ("Insufficient packet space for all options.");
}

/* Copy the option data specified by code from the packet structure's
   option array into an option buffer specified by buf and buflen,
   updating stored_length[code] to reflect the amount of code's option
   data that has been stored so far.   Return 1 if all the option data
   has been stored. */
   
int store_option (options, code, buffer, buflen, stored_length)
	struct tree_cache **options;
	unsigned char code;
	unsigned char *buffer;
	int buflen;
	int *stored_length;
{
	int length = options [code] -> len - stored_length [code];
	int bufix = 0;
	if (length > buflen) {
		length = buflen;
	}

	/* If the option's length is more than 255, we must store it
	   in multiple hunks.   Store 255-byte hunks first. */
	/* XXX Might a client lose its cookies if options aren't
	   chunked out so that each chunk is aligned to the size
	   of the data being represented? */
	while (length) {
		unsigned char incr = length > 255 ? 255 : length;
		buffer [bufix] = code;
		buffer [bufix + 1] = incr;
		memcpy (buffer + bufix + 2, (options [code] -> value
					     + stored_length [code]), incr);
		length -= incr;
		stored_length [code] += incr;
		bufix += 2 + incr;
	}
	return bufix;
}

/* Format the specified option so that a human can easily read it. */

char *pretty_print_option (code, data, len)
	unsigned char code;
	unsigned char *data;
	int len;
{
	static char optbuf [32768]; /* XXX */
	int hunksize = 0;
	int numhunk = -1;
	int numelem = 0;
	char fmtbuf [32];
	int i, j;
	char *op = optbuf;
	unsigned char *dp = data;
	struct in_addr foo;

	/* Figure out the size of the data. */
	for (i = 0; dhcp_options [code].format [i]; i++) {
		if (!numhunk) {
			warn ("%s: Excess information in format string: %s\n",
			      dhcp_options [code].name,
			      &(dhcp_options [code].format [i]));
			break;
		}
		numelem++;
		fmtbuf [i] = dhcp_options [code].format [i];
		switch (dhcp_options [code].format [i]) {
		      case 'A':
			--numelem;
			fmtbuf [i] = 0;
			numhunk = 0;
			break;
		      case 't':
			fmtbuf [i] = 't';
			fmtbuf [i + 1] = 0;
			numhunk = -2;
			break;
		      case 'I':
		      case 'l':
		      case 'L':
			hunksize += 4;
			break;
		      case 's':
		      case 'S':
			hunksize += 2;
			break;
		      case 'b':
		      case 'B':
		      case 'f':
			hunksize++;
			break;
		      case 'e':
			break;
		      default:
			warn ("%s: garbage in format string: %s\n",
			      dhcp_options [code].name,
			      &(dhcp_options [code].format [i]));
			break;
		} 
	}

	/* Check for too few bytes... */
	if (hunksize > len) {
		warn ("%s: expecting at least %d bytes; got %d",
		      dhcp_options [code].name,
		      hunksize, len);
		return "<error>";
	}
	/* Check for too many bytes... */
	if (numhunk == -1 && hunksize < len)
		warn ("%s: %d extra bytes",
		      dhcp_options [code].name,
		      len - hunksize);

	/* If this is an array, compute its size. */
	if (!numhunk)
		numhunk = len / hunksize;
	/* See if we got an exact number of hunks. */
	if (numhunk > 0 && numhunk * hunksize < len)
		warn ("%s: %d extra bytes at end of array\n",
		      dhcp_options [code].name,
		      len - numhunk * hunksize);

	/* A one-hunk array prints the same as a single hunk. */
	if (numhunk < 0)
		numhunk = 1;

	/* Cycle through the array (or hunk) printing the data. */
	for (i = 0; i < numhunk; i++) {
		for (j = 0; j < numelem; j++) {
			switch (fmtbuf [j]) {
			      case 't':
				strcpy (op, dp);
				break;
			      case 'I':
				foo.s_addr = htonl (getULong (dp));
				strcpy (op, inet_ntoa (foo));
				dp += 4;
				break;
			      case 'l':
				sprintf (op, "%ld", getLong (dp));
				dp += 4;
				break;
			      case 'L':
				sprintf (op, "%ld", getULong (dp));
				dp += 4;
				break;
			      case 's':
				sprintf (op, "%d", getShort (dp));
				dp += 2;
				break;
			      case 'S':
				sprintf (op, "%d", getUShort (dp));
				dp += 2;
				break;
			      case 'b':
				sprintf (op, "%d", *(char *)dp++);
				break;
			      case 'B':
				sprintf (op, "%d", *dp++);
				break;
			      case 'f':
				strcpy (op, *dp++ ? "true" : "false");
				break;
			      default:
				warn ("Unexpected format code %c", fmtbuf [j]);
			}
			op += strlen (op);
			*op++ = ' ';
		}
	}
	*--op = 0;
	return optbuf;
}

			
		
