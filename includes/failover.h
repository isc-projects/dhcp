/* failover.h

   Definitions for address trees... */

/*
 * Copyright (c) 1999 Internet Software Consortium.
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

struct failover_option {
	int code;
	char *name;
	enum { FT_UINT8, FT_IPADDR, FT_UINT32, FT_BYTES, FT_DDNS,
	       FT_UINT16, FT_TEXT, FT_UNDEF, FT_DIGEST } data_type;
	int num_present;
	int data_offset;
};

#define FM_OFFSET(x)	((char *)(((struct failover_message *)0).x) - \
			 (char *)(((struct failover_message *)0)))

#define FTO_BINDING_STATUS		1
#define FTB_BINDING_STATUS			0x00000002
#define FTO_ASSIGNED_IP_ADDRESS		2
#define FTB_ASSIGNED_IP_ADDRESS			0x00000004
#define FTO_SERVER_ADDR			3
#define FTB_SERVER_ADDR				0x00000008
#define FTO_ADDRESSES_TRANSFERRED	4
#define FTB_ADDRESSES_TRANSFERRED		0x00000010
#define FTO_CLIENT_IDENTIFIER		5
#define FTB_CLIENT_IDENTIFIER			0x00000020
#define FTO_CLIENT_HARDWARE_ADDRESS	6
#define FTB_CLIENT_HARDWARE_ADDRESS		0x00000040
#define FTO_DDNS			7
#define FTB_DDNS				0x00000080
#define FTO_REJECT_REASON		8
#define FTB_REJECT_REASON			0x00000100
#define FTO_MESSAGE			9
#define FTB_MESSAGE				0x00000200
#define FTO_MCLT			10
#define FTB_MCLT				0x00000400
#define FTO_VENDOR_CLASS		11
#define FTB_VENDOR_CLASS			0x00000800
#define FTO_EXPIRY			13
#define FTB_EXPIRY				0x00002000
#define FTO_POTENTIAL_EXPIRY		14
#define FTB_POTENTIAL_EXPIRY			0x00004000
#define FTO_GRACE_EXPIRY		15
#define FTB_GRACE_EXPIRY			0x00008000
#define FTO_CLTT			16
#define FTB_CLTT				0x00010000
#define FTO_STOS			17
#define FTB_STOS				0x00020000
#define FTO_SERVER_STATE		18
#define FTB_SERVER_STATE			0x00040000
#define FTO_SERVER_FLAGS		19
#define FTB_SERVER_FLAGS			0x00080000
#define FTO_VENDOR_OPTIONS		20
#define FTB_VENDOR_OPTIONS			0x00100000
#define FTO_MAX_UNACKED			21
#define FTB_MAX_UNACKED				0x00200000
#define FTO_RECEIVE_TIMER		23
#define FTB_RECEIVE_TIMER			0x00800000
#define FTO_HBA				24
#define FTB_HBA					0x01000000
#define FTO_MESSAGE_DIGEST		25
#define FTB_MESSAGE_DIGEST			0x02000000
#define FTO_PROTOCOL_VERSION		26
#define FTB_PROTOCOL_VERSION			0x04000000
#define FTO_TLS_REQUEST			27
#define FTB_TLS_REQUEST				0x08000000
#define FTO_TLS_REPLY			28
#define FTB_TLS_REPLY				0x10000000
#define FTO_REQUEST_OPTIONS		29
#define FTB_REQUEST_OPTIONS			0x20000000
#define FTO_REPLY_OPTIONS		30
#define FTB_REPLY_OPTIONS			0x40000000
#define FTO_MAX				FTO_REPLY_OPTIONS

#define FTM_POOLREQ		1
#define FTM_POOLRESP		2
#define FTM_BNDUPD		3
#define FTM_BNDACK		4
#define FTM_CONNECT		5
#define FTM_CONNECTACK		6
#define FTM_UPDREQ		7
#define FTM_UPDDONE		8
#define FTM_UPDREQALL		9
#define FTM_STATE		10
#define FTM_CONTACT		11
#define FTM_DISCONNECT		12
