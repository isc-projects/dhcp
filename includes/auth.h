/* dhcpd.h

   Definitions for dhcpd... */

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


/* State structure for ongoing computation of a packet signature. */

struct signature_state {
	u_int8_t *algorithm_state;
	u_int8_t *output;
	int output_len;
	void (*update) (u_int8_t *, u_int8_t *, u_int8_t *);
	void (*final) (u_int8_t *, u_int8_t *);
};

struct auth_key {
	int length;
	u_int8_t data [1];
};

