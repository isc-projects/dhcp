/* convert.c

   Safe copying of option values into and out of the option buffer, which
   can't be assumed to be aligned. */

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
"$Id: convert.c,v 1.9 1999/07/06 16:51:19 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

u_int32_t getULong (buf)
	unsigned char *buf;
{
	unsigned long ibuf;

	memcpy (&ibuf, buf, sizeof (u_int32_t));
	return ntohl (ibuf);
}

int32_t getLong (buf)
	unsigned char *buf;
{
	long ibuf;

	memcpy (&ibuf, buf, sizeof (int32_t));
	return ntohl (ibuf);
}

u_int32_t getUShort (buf)
	unsigned char *buf;
{
	unsigned short ibuf;

	memcpy (&ibuf, buf, sizeof (u_int16_t));
	return ntohs (ibuf);
}

int32_t getShort (buf)
	unsigned char *buf;
{
	short ibuf;

	memcpy (&ibuf, buf, sizeof (int16_t));
	return ntohs (ibuf);
}

void putULong (obuf, val)
	unsigned char *obuf;
	u_int32_t val;
{
	u_int32_t tmp = htonl (val);
	memcpy (obuf, &tmp, sizeof tmp);
}

void putLong (obuf, val)
	unsigned char *obuf;
	int32_t val;
{
	int32_t tmp = htonl (val);
	memcpy (obuf, &tmp, sizeof tmp);
}

void putUShort (obuf, val)
	unsigned char *obuf;
	u_int32_t val;
{
	u_int16_t tmp = htons (val);
	memcpy (obuf, &tmp, sizeof tmp);
}

void putShort (obuf, val)
	unsigned char *obuf;
	int32_t val;
{
	int16_t tmp = htons (val);
	memcpy (obuf, &tmp, sizeof tmp);
}

void putUChar (obuf, val)
	unsigned char *obuf;
	u_int32_t val;
{
	*obuf = val;
}

u_int32_t getUChar (obuf)
	unsigned char *obuf;
{
	return obuf [0];
}

int converted_length (buf, base, width)
	unsigned char *buf;
	unsigned int base;
	unsigned int width;
{
	u_int32_t number;
	int column;
	int power = 1;
	int newcolumn = base;

	if (base > 16)
		return 0;

	if (width == 1)
		number = getUChar (buf);
	else if (width == 2)
		number = getUShort (buf);
	else if (width == 4)
		number = getULong (buf);

	do {
		column = newcolumn;

		if (number < column)
			return power;
		power++;
		newcolumn = column * base;
		/* If we wrap around, it must be the next power of two up. */
	} while (column > newcolumn);

	return power;
}

int binary_to_ascii (outbuf, inbuf, base, width)
	unsigned char *outbuf;
	unsigned char *inbuf;
	unsigned int base;
	unsigned int width;
{
	u_int32_t number;
	static char h2a [] = "0123456789abcdef";
	int power = 0;
	int i, j;

	if (base > 16)
		return 0;

	if (width == 1)
		number = getUChar (inbuf);
	else if (width == 2)
		number = getUShort (inbuf);
	else if (width == 4)
		number = getULong (inbuf);

	for (i = 0; number; i++) {
		outbuf [i] = h2a [number % base];
		number /= base;
		power++;
	}

	for (j = 0; j < i / 2; j++) {
		unsigned char t = outbuf [j];
		outbuf [j] = outbuf [i - j - 1];
		outbuf [i - j - 1] = t;
	}
	return power;
}
