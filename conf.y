/* conf.y

   Dhcpd configuration file grammar... */

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

%{
#include "dhcpd.h"
%}

%token HOST HARDWARE ETHERNET FILENAME FIXED_ADDRESS STRING
%token OCTET COLON DOT SEMI TOKEN OPTION

%start	config

%%
config	:	config_items
	;


config_items:	/* blank */
	|	config_item
	|	config_items config_item
	;

config_item:	host_decl
	;

host_decl:	HOST hostname packet_decls SEMI
	;

hostname:	token
	|	token DOT hostname
	;

packet_decls:	/* empty */
	|	packet_decl
	|	packet_decls packet_decl
	;

packet_decl:	hardware_decl
	|	filename_decl
	|	fixed_addr_decl
	|	option_decl
	;

hardware_decl:	HARDWARE ETHERNET OCTET COLON OCTET COLON OCTET
				        COLON OCTET COLON OCTET COLON OCTET
	;

filename_decl:	FILENAME STRING
	;

fixed_addr_decl: FIXED_ADDRESS host_address
	;

host_address:	hostname
	|	ip_address
	;

ip_address:	OCTET DOT OCTET
	|	OCTET DOT OCTET DOT OCTET DOT OCTET
	;

option_decl:	OPTION token STRING
	;

token:		reserved_word
	|	TOKEN
	;

reserved_word:	HOST
	|	HARDWARE
	|	ETHERNET
	|	FILENAME
	|	FIXED_ADDRESS
	|	OPTION
	;

