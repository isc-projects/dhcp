/* options.c

   DHCP options parsing and reassembly. */

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
"$Id: options.c,v 1.27 1998/02/06 01:18:33 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
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
			     packet -> packet_length - DHCP_FIXED_NON_UDP - 4);
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

		/* If this is a Relay Agent Information option, we must
		   handle it specially. */
		if (code == DHO_DHCP_AGENT_OPTIONS) {
			if (!parse_agent_information_option (packet,
							     len, &s [2])) {
				warn ("malformed agent information option.");
			}

		/* If we haven't seen this option before, just make
		   space for it and copy it there. */
		} else if (!packet -> options [code].data) {
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
				malloc (len
					+ packet -> options [code].len
					+ 1);
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

/* Parse a Relay Agent Information option and put it at the end of the
   list of such options on the specified packet. */

int parse_agent_information_option (packet, len, data)
	struct packet *packet;
	int len;
	u_int8_t *data;
{
	struct agent_options *a, **tail;
	struct option_tag *t, *oth = 0, **ott = &oth;
	u_int8_t *op = data, *max = data + len;

	/* Parse the agent information option suboptions. */
	while (op < max) {
		/* Check for overflow. */
		if (op + 1 == max || op + op [1] + 2 > max)
			return 0;
		/* Make space for this suboption. */
 		t = (struct option_tag *)malloc (op [1] + 1 + sizeof *t);
		if (!t)
			error ("can't allocate space for option tag data.");

		/* Link it in at the tail of the list. */
		t -> next = (struct option_tag *)0;
		*ott = t;
		ott = &t -> next;
		
		/* Copy the option data in in its raw form. */
		memcpy (t -> data, op, op [1] + 2);
		op += op [1] + 2;
	}

	/* Make an agent options structure to put on the list. */
	a = (struct agent_options *)malloc (sizeof *a);
	if (!a)
		error ("can't allocate space for agent option structure.");

	/* Find the tail of the list. */
	for (tail = &packet -> agent_options; *tail; tail = &((*tail) -> next))
		;
	*tail = a;
	a -> next = (struct agent_options *)0;
	a -> first = oth;
	a -> length = len;

	return 1;
}

/* cons options into a big buffer, and then split them out into the
   three seperate buffers if needed.  This allows us to cons up a set
   of vendor options using the same routine. */

int cons_options (inpacket, outpacket, mms, options, agent_options,
		  overload, terminate, bootpp)
	struct packet *inpacket;
	struct dhcp_packet *outpacket;
	int mms;
	struct tree_cache **options;
	struct agent_options *agent_options;
	int overload;	/* Overload flags that may be set. */
	int terminate;
	int bootpp;
{
	unsigned char priority_list [300];
	int priority_len;
	unsigned char buffer [4096];	/* Really big buffer... */
	int main_buffer_size;
	int mainbufix, bufix, agentix;
	int option_size;
	int length;

	/* If there's a Maximum Message Size option in the incoming packet
	   and no alternate maximum message size has been specified, take the
	   one in the packet. */

	if (!mms &&
	    inpacket && inpacket -> options [DHO_DHCP_MAX_MESSAGE_SIZE].data) {
		mms = getUShort (inpacket ->
				 options [DHO_DHCP_MAX_MESSAGE_SIZE].data);
	}

	/* If the client has provided a maximum DHCP message size,
	   use that; otherwise, if it's BOOTP, only 64 bytes; otherwise
	   use up to the minimum IP MTU size (576 bytes). */
	/* XXX if a BOOTP client specifies a max message size, we will
	   honor it. */

	if (mms) {
		main_buffer_size = mms - DHCP_FIXED_LEN;

		/* Enforce a minimum packet size... */
		if (main_buffer_size < (576 - DHCP_FIXED_LEN))
			main_buffer_size = 576 - DHCP_FIXED_LEN;
	} else if (bootpp)
		main_buffer_size = 64;
	else
		main_buffer_size = 576 - DHCP_FIXED_LEN;

	/* Set a hard limit at the size of the output buffer. */
	if (main_buffer_size > sizeof buffer)
		main_buffer_size = sizeof buffer;

	/* Preload the option priority list with mandatory options. */
	priority_len = 0;
	priority_list [priority_len++] = DHO_DHCP_MESSAGE_TYPE;
	priority_list [priority_len++] = DHO_DHCP_SERVER_IDENTIFIER;
	priority_list [priority_len++] = DHO_DHCP_LEASE_TIME;
	priority_list [priority_len++] = DHO_DHCP_MESSAGE;

	/* If the client has provided a list of options that it wishes
	   returned, use it to prioritize.  Otherwise, prioritize
	   based on the default priority list. */

	if (inpacket &&
	    inpacket -> options [DHO_DHCP_PARAMETER_REQUEST_LIST].data) {
		memcpy (&priority_list [priority_len],
			inpacket -> options
				[DHO_DHCP_PARAMETER_REQUEST_LIST].data,
			inpacket -> options
				[DHO_DHCP_PARAMETER_REQUEST_LIST].len);
		priority_len +=
			inpacket -> options
				[DHO_DHCP_PARAMETER_REQUEST_LIST].len;
	} else {
		memcpy (&priority_list [priority_len],
			dhcp_option_default_priority_list,
			sizeof_dhcp_option_default_priority_list);
		priority_len += sizeof_dhcp_option_default_priority_list;
	}

	/* Copy the options into the big buffer... */
	option_size = store_options (buffer,
				     (main_buffer_size - 7 +
				      ((overload & 1) ? DHCP_FILE_LEN : 0) +
				      ((overload & 2) ? DHCP_SNAME_LEN : 0)),
				     options, priority_list, priority_len,
				     main_buffer_size,
				     (main_buffer_size +
				      ((overload & 1) ? DHCP_FILE_LEN : 0)),
				     terminate);

	/* Put the cookie up front... */
	memcpy (outpacket -> options, DHCP_OPTIONS_COOKIE, 4);
	mainbufix = 4;

	/* If we're going to have to overload, store the overload
	   option at the beginning.  If we can, though, just store the
	   whole thing in the packet's option buffer and leave it at
	   that. */
	if (option_size <= main_buffer_size - mainbufix) {
		memcpy (&outpacket -> options [mainbufix],
			buffer, option_size);
		mainbufix += option_size;
		if (mainbufix < main_buffer_size) {
			agentix = mainbufix;
			outpacket -> options [mainbufix++]
				= DHO_END;
		} else
			agentix = mainbufix;
		length = DHCP_FIXED_NON_UDP + mainbufix;
	} else {
		outpacket -> options [mainbufix++] =
			DHO_DHCP_OPTION_OVERLOAD;
		outpacket -> options [mainbufix++] = 1;
		if (option_size > main_buffer_size - mainbufix + DHCP_FILE_LEN)
			outpacket -> options [mainbufix++] = 3;
		else
			outpacket -> options [mainbufix++] = 1;

		memcpy (&outpacket -> options [mainbufix],
			buffer, main_buffer_size - mainbufix);
		length = DHCP_FIXED_NON_UDP + main_buffer_size;
		agentix = main_buffer_size;

		bufix = main_buffer_size - mainbufix;
		if (overload & 1) {
			if (option_size - bufix <= DHCP_FILE_LEN) {
				memcpy (outpacket -> file,
					&buffer [bufix], option_size - bufix);
				mainbufix = option_size - bufix;
				if (mainbufix < DHCP_FILE_LEN)
					outpacket -> file [mainbufix++]
						= DHO_END;
				while (mainbufix < DHCP_FILE_LEN)
					outpacket -> file [mainbufix++]
						= DHO_PAD;
			} else {
				memcpy (outpacket -> file,
					&buffer [bufix], DHCP_FILE_LEN);
				bufix += DHCP_FILE_LEN;
			}
		}
		if ((overload & 2) && option_size < bufix) {
			memcpy (outpacket -> sname,
				&buffer [bufix], option_size - bufix);

			mainbufix = option_size - bufix;
			if (mainbufix < DHCP_SNAME_LEN)
				outpacket -> file [mainbufix++]
					= DHO_END;
			while (mainbufix < DHCP_SNAME_LEN)
				outpacket -> file [mainbufix++]
					= DHO_PAD;
		}
	}

	/* We tack any agent options onto the end of the packet after
	   we've put it together. */
	if (agent_options) {
	    int len = 0;
	    struct agent_options *a;
	    struct option_tag *o;

	    /* Cycle through the options, appending them to the
	       buffer. */
	    for (a = agent_options; a; a = a -> next) {
		if (agentix + a -> length + 3 + DHCP_FIXED_LEN <=
		    dhcp_max_agent_option_packet_length) {
			outpacket ->
				options [agentix++] = DHO_DHCP_AGENT_OPTIONS;
			outpacket -> options [agentix++] = a -> length;
			for (o = a -> first; o; o = o -> next) {
			    memcpy (&outpacket -> options [agentix],
				    o -> data, o -> data [1] + 2);
			    agentix += o -> data [1] + 2;
		    }
		}
	    }

	    /* Reterminate the packet. */
	    outpacket -> options [agentix++] = DHO_END;

	    /* Recompute the length, which may now be higher than the
	       client can accept but should be okay for the relay agent. */
	    length = agentix + DHCP_FIXED_NON_UDP;
	}
		
	return length;
}

/* Store all the requested options into the requested buffer. */

int store_options (buffer, buflen, options, priority_list, priority_len,
		   first_cutoff, second_cutoff, terminate)
	unsigned char *buffer;
	int buflen;
	struct tree_cache **options;
	unsigned char *priority_list;
	int priority_len;
	int first_cutoff, second_cutoff;
	int terminate;
{
	int bufix = 0;
	int option_stored [256];
	int i;
	int ix;
	int tto;

	/* Zero out the stored-lengths array. */
	memset (option_stored, 0, sizeof option_stored);

	/* Copy out the options in the order that they appear in the
	   priority list... */
	for (i = 0; i < priority_len; i++) {
		/* Code for next option to try to store. */
		int code = priority_list [i];
		int optstart;

		/* Number of bytes left to store (some may already
		   have been stored by a previous pass). */
		int length;

		/* If no data is available for this option, skip it. */
		if (!options [code]) {
			continue;
		}

		/* The client could ask for things that are mandatory,
		   in which case we should avoid storing them twice... */
		if (option_stored [code])
			continue;
		option_stored [code] = 1;

		/* Find the value of the option... */
		if (!tree_evaluate (options [code])) {
			continue;
		}

		/* We should now have a constant length for the option. */
		length = options [code] -> len;

		/* Do we add a NUL? */
		if (terminate && dhcp_options [code].format [0] == 't') {
			length++;
			tto = 1;
		} else {
			tto = 0;
		}

		/* Try to store the option. */

		/* If the option's length is more than 255, we must store it
		   in multiple hunks.   Store 255-byte hunks first.  However,
		   in any case, if the option data will cross a buffer
		   boundary, split it across that boundary. */

		ix = 0;

		optstart = bufix;
		while (length) {
			unsigned char incr = length > 255 ? 255 : length;

			/* If this hunk of the buffer will cross a
			   boundary, only go up to the boundary in this
			   pass. */
			if (bufix < first_cutoff &&
			    bufix + incr > first_cutoff)
				incr = first_cutoff - bufix;
			else if (bufix < second_cutoff &&
				 bufix + incr > second_cutoff)
				incr = second_cutoff - bufix;

			/* If this option is going to overflow the buffer,
			   skip it. */
			if (bufix + 2 + incr > buflen) {
				bufix = optstart;
				break;
			}

			/* Everything looks good - copy it in! */
			buffer [bufix] = code;
			buffer [bufix + 1] = incr;
			if (tto && incr == length) {
				memcpy (buffer + bufix + 2,
					options [code] -> value + ix,
					incr - 1);
				buffer [bufix + 2 + incr - 1] = 0;
			} else {
				memcpy (buffer + bufix + 2,
					options [code] -> value + ix, incr);
			}
			length -= incr;
			ix += incr;
			bufix += 2 + incr;
		}
	}
	return bufix;
}

/* Format the specified option so that a human can easily read it. */

char *pretty_print_option (code, data, len, emit_commas, emit_quotes)
	unsigned int code;
	unsigned char *data;
	int len;
	int emit_commas;
	int emit_quotes;
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
	char comma;

	/* Code should be between 0 and 255. */
	if (code > 255)
		error ("pretty_print_option: bad code %d\n", code);

	if (emit_commas)
		comma = ',';
	else
		comma = ' ';
	
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
		      case 'X':
			fmtbuf [i] = 'x';
			fmtbuf [i + 1] = 0;
			hunksize++;
			numhunk = 0;
			comma = ':';
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
				if (emit_quotes)
					*op++ = '"';
				strcpy (op, dp);
				op += strlen (dp);
				if (emit_quotes)
					*op++ = '"';
				*op = 0;
				break;
			      case 'I':
				foo.s_addr = htonl (getULong (dp));
				strcpy (op, inet_ntoa (foo));
				dp += 4;
				break;
			      case 'l':
				sprintf (op, "%ld", (long)getLong (dp));
				dp += 4;
				break;
			      case 'L':
				sprintf (op, "%ld",
					 (unsigned long)getULong (dp));
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
			      case 'x':
				sprintf (op, "%x", *dp++);
				break;
			      case 'f':
				strcpy (op, *dp++ ? "true" : "false");
				break;
			      default:
				warn ("Unexpected format code %c", fmtbuf [j]);
			}
			op += strlen (op);
			if (j + 1 < numelem && comma != ':')
				*op++ = ' ';
		}
		if (i + 1 < numhunk) {
			*op++ = comma;
		}
		
	}
	return optbuf;
}

void do_packet (interface, packbuf, len, from_port, from, hfrom)
	struct interface_info *interface;
	unsigned char *packbuf;
	int len;
	unsigned short from_port;
	struct iaddr from;
	struct hardware *hfrom;
{
	struct packet tp;
	struct dhcp_packet tdp; /* XXX This < 1500 bytes! */

	memcpy (&tdp, packbuf, len);
	memset (&tp, 0, sizeof tp);
	tp.raw = &tdp;
	tp.packet_length = len;
	tp.client_port = from_port;
	tp.client_addr = from;
	tp.interface = interface;
	tp.haddr = hfrom;
	
	parse_options (&tp);
	if (tp.options_valid &&
	    tp.options [DHO_DHCP_MESSAGE_TYPE].data)
		tp.packet_type =
			tp.options [DHO_DHCP_MESSAGE_TYPE].data [0];
	if (tp.packet_type)
		dhcp (&tp);
	else
		bootp (&tp);

	/* XXX what about freeing the options ?!? */
}

