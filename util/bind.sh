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

# $Id: bind.sh,v 1.17 2011/02/25 20:08:55 sar Exp $

# Get the bind distribution for the libraries
# This script is used to build the DHCP distribution and shouldn't be shipped
#
# Usage: sh bind.sh <DHCP version>
#
#

topdir=`pwd`
binddir=$topdir/bind

case $# in 
    1)
	case "$1" in 
	###
	### Robie calls this script with the building branch name so we can
	### build with BIND9 HEAD for the relevant branch we would release
	### with.
	###
	### XXX: We can't use the 'snapshot' syntax right now because kit.sh
	### pulls the version.tmp off the branch name, and then stores a
	### tarball with vastly different values.  So the version.tmp can not
	### be used to chdir down into the directory that is unpacked.
	###
	v4_2) noSNAP=snapshot BINDTAG=v9_7 ;;
	HEAD|v[0-9]_[0-9].*) noSNAP=snapshot BINDTAG=HEAD ;;
	###
	### For ease of use, this records the sticky tag of versions
	### released with each point release.
	###
	4.2.1) BINDTAG=v9_8_0 ;;
	4.2.1rc1) BINDTAG=v9_8_0rc1 ;;
	4.2.1b1) BINDTAG=v9_8_0b1 ;;
	4.2.0rc1|4.2.0) BINDTAG=v9_7_1 ;;
	4.2.0b2) BINDTAG=v9_7_1rc1 ;;
	4.2.0b1) BINDTAG=v9_7_0_P1 ;;
	4.2.0a2|4.2.0a1) BINDTAG=v9_7_0b3 ;;
	*) echo "bind.sh: unsupported version: $1" >&2
	   exit 1
	   ;;
	esac
	;;
    *) echo "usage: sh bind.sh [<branch>|<version>]" >&2
       exit 1
       ;;
esac

# Delete all previous bind stuff
rm -rf bind

# Make and move to our directory for all things bind
mkdir $binddir
cp util/Makefile.bind bind/Makefile
cd $binddir

# Get the bind release kit shell script
cvs checkout -p -r $BINDTAG bind9/util/kit.sh > kit.sh

# Create the bind tarball, which has the side effect of
# setting up the bind directory we will use for building
# the export libraries
sh kit.sh $SNAP $BINDTAG $binddir

. ./version.tmp

version=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}
bindsrcdir=bind-$version
mm=${MAJORVER}.${MINORVER}

# move the tar file to a known place for use by the make dist command
mv bind-${mm}*.tar.gz bind.tar.gz

# temporary hack to allow testing when using snapshots
#mv $binddir/bind-9.7* $binddir/$bindsrcdir

# Run the script to build and install the export libraries
# Let make do this now.
#sh $topdir/util/bindlib.sh $binddir $bindsrcdir

