/* cdefs.h

   Standard C definitions... */

/*
 * Copyright (c) 1995 RadioMail Corporation.  All rights reserved.
 * Copyright (c) 1996-1999 Internet Software Consortium.
 *
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
 *
 * This software was written for RadioMail Corporation by Ted Lemon
 * under a contract with Vixie Enterprises.   Further modifications have
 * been made for the Internet Software Consortium under a contract
 * with Vixie Laboratories.
 */

#if !defined (__ISC_DHCP_CDEFS_H__)
#define __ISC_DHCP_CDEFS_H__
/* Delete attributes if not gcc or not the right version of gcc. */
#if !defined(__GNUC__) || __GNUC__ < 2 || \
        (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define __attribute__(x)
#endif

#if (defined (__GNUC__) || defined (__STDC__)) && !defined (BROKEN_ANSI)
#define PROTO(x)	x
#define KandR(x)
#define ANSI_DECL(x)	x
#if defined (__GNUC__)
#define INLINE		inline
#else
#define INLINE
#endif /* __GNUC__ */
#else
#define PROTO(x)	()
#define KandR(x)	x
#define ANSI_DECL(x)
#define INLINE
#endif /* __GNUC__ || __STDC__ */
#endif /* __ISC_DHCP_CDEFS_H__ */
