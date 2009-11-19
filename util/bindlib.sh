#!/bin/sh
#
# Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: bindlib.sh,v 1.5 2009/11/19 23:49:57 sar Exp $

# Configure, build and install the bind export libraries for use by DHCP
#
# Usage: sh bindlib.sh <bind directory> <bind source directory>
# The intention is for this script to be called by other scrips
# (bind.sh or bindcus.sh) rather than be called directly.
#
# <bind directory> = directory for bind stuff within DHCP, typically
# <dhcp>/bind
#
# <bind source directory> = directory for the unpacked bind source code
# typically <dhcp>/bind/bind-<version>
#

binddir="$1"
bindsrcdir="$2"

gmake=
for x in gmake gnumake make; do
	if $x --version 2>/dev/null | grep GNU > /dev/null; then
		gmake=$x
		break;
	fi
done
if test -z "$gmake"; then
	echo "unable to find gmake" 1>&2
	exit 1;
fi

# Configure the export libraries
# Currently disable the epoll and devpoll options as they don't interact
# well with the DHCP code.
cd $bindsrcdir
./configure --disable-epoll --disable-devpoll --without-openssl --without-libxml2 --enable-exportlib --enable-threads=no --with-export-includedir=$binddir/include --with-export-libdir=$binddir/lib > $binddir/configure.log

# Build the export libraries
cd lib/export
MAKE=$gmake $gmake > $binddir/build.log

# Install the libraries and includes
MAKE=$gmake $gmake install > $binddir/install.log
