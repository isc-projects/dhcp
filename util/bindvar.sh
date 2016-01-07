#!/bin/sh
#
# Copyright (C) 2009,2015  Internet Systems Consortium, Inc. ("ISC")
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

# $Id: bindvar.sh,v 1.2 2009/12/02 20:43:52 sar Exp $

# Create a file with the base directory and gmake path for
# use by the bind/Makefile, we do this to minimize portability
# concerns.

# Bind requires a GNU style make to compile, if we can't find one
# exit with a non-zero status, otherwise exit with success (i.e. 0)

binddir=`pwd`
gmake=
for x in gmake gnumake make; do
	if $x --version 2>/dev/null | grep GNU > /dev/null; then
		gmake=$x
		break;
	fi
done

if [ -z $gmake ]
then
    echo "$0: Building Bind requires a GNU style make tool and none were found in your path. We tried gmake, gnumake, and make."
    exit 1
fi

cat <<EOF > bind/bindvar.tmp
binddir=$binddir/bind
GMAKE=$gmake
EOF

exit 0
