#!/bin/sh
#
# Copyright (C) 2009-2022  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# $Id: bind.sh,v 1.32 2012/05/24 17:50:00 sar Exp $

# Get the bind distribution for the libraries
# This script is used to build the DHCP distribution and shouldn't be shipped
#
# Usage: sh bind.sh [--remote=<path>] <DHCP version>
#
# Normally remote will only be used by Robie
#
#

topdir=`pwd`
binddir=$topdir/bind

# repo_host and repo_path are used together to from urls for wget calls
# to fetch the version and kit.sh files, and then also as the --remote
# argument passed into kit.sh
repo_host="gitlab.isc.org"
repo_path="isc-projects/bind9"

while :
do
	case "${1:-}" in
	--repo_host=*)
		repo_host="${1}";
		shift
		continue
		;;
	--repo_path=*)
		repo_path="${1}";
		shift
		continue
		;;
	esac
	break;
done

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
	v4_2) noSNAP=snapshot BINDTAG=v9_9 ;;
	v4_3) noSNAP=snapshot BINDTAG=v9_9 ;;
	v4_4) noSNAP=snapshot BINDTAG=v9_11 ;;
	HEAD|v[0-9]_[0-9].*) noSNAP=snapshot BINDTAG=v9_11 ;;
	### HEAD|v[0-9]_[0-9].*) noSNAP=snapshot BINDTAG=HEAD ;;
	###
	### For ease of use, this records the sticky tag of versions
	### released with each point release.
	###
	4.4.3) noSNAP=snapshot BINDTAG=v9_11_36 ;;
	4.4.2) noSNAP=snapshot BINDTAG=v9_11_14 ;;
	4.4.2b1) noSNAP=snapshot BINDTAG=v9_11_14 ;;
	4.4.2-dev) noSNAP=snapshot BINDTAG=v9_11_8 ;;
	4.4.1) noSNAP=snapshot BINDTAG=v9_11_2_P1 ;;
	4.4.0) noSNAP=snapshot BINDTAG=v9_11_2_P1 ;;
	4.4.0b1) noSNAP=snapshot BINDTAG=v9_11_2 ;;
	4.4.0a1) noSNAP=snapshot BINDTAG=v9_11_2 ;;
	4.3.4|4.3.4b1) BINDTAG=v9_9_8_P4 ;;
	4.3.3) BINDTAG=v9_9_7_P3 ;;
	4.3.3b1) BINDTAG=v9_9_7_P2 ;;
	4.3.2|4.3.2rc2) BINDTAG=v9_9_7 ;;
	4.3.2rc1) BINDTAG=v9_9_7rc2 ;;
	4.3.2b1) BINDTAG=v9_9_7rc1 ;;
	4.3.2.pre-beta) BINDTAG=v9_9_5_P1 ;;
	4.3.1b1|4.3.1rc1|4.3.1) BINDTAG=v9_9_5_P1 ;;
	4.3.0) BINDTAG=v9_9_5 ;;
	4.3.0rc1) BINDTAG=v9_9_5rc2 ;;
	4.3.0b1) BINDTAG=v9_9_5rc1 ;;
	4.3.0a1) BINDTAG=v9_9_5b1 ;;
	4.2.6) BINDTAG=v9_9_5 ;;
	4.2.6rc1) BINDTAG=v9_9_5rc2 ;;
	4.2.6b1) BINDTAG=v9_9_5rc1 ;;
	4.2.5b1|4.2.5rc1|4.2.5) BINDTAG=v9_8_4_P1 ;;
	4.2.4rc2|4.2.4) BINDTAG=v9_8_3 ;;
	4.2.4b1|4.2.4rc1) BINDTAG=v9_8_2 ;;
	4.2.3-P1|4.2.3-P2) BINDTAG=v9_8_1_P1 ;;
	4.2.3rc1|4.2.3) BINDTAG=v9_8_1 ;;
	4.2.2rc1|4.2.2) BINDTAG=v9_8_0_P4 ;;
	4.2.1|4.2.1-P1|4.2.2b1) BINDTAG=v9_8_0 ;;
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
    *) echo "usage: sh bind.sh [--repo_host=<host>] [--repo_path=<project path>] ( <branch>|<version> )" >&2
       exit 1
       ;;
esac

if test -d bind/bind9/.git
then
	cp util/Makefile.bind.in bind/Makefile.in
	rm -rf bind/include bind/lib
	cd bind/bind9
	test -f Makefile && make distclean
	git fetch
	git checkout $BINDTAG && test -n "${noSNAP}" && \
	    git merge --ff-only HEAD
else
	# Delete all previous bind stuff
	rm -rf bind

	# Make and move to our directory for all things bind
	mkdir $binddir
	cp util/Makefile.bind.in bind/Makefile.in
	cp util/bind-kit.sh bind/kit.sh
	cd $binddir

	# Get the bind version file and move it to version.tmp
	if type wget
	then
		wget https://$repo_host/$repo_path/raw/$BINDTAG/version ||
		{ echo "Fetch of version file failed" ; exit -1; }
	elif type fetch
	then
		fetch https://$repo_host/$repo_path/raw/$BINDTAG/version ||
		{ echo "Fetch of version file failed" ; exit -1; }
	else
		echo "Fetch of version file failed"
		exit 1
	fi
	mv version version.tmp

	# Now the bind release kit shell script is distributed

	# Create the bind tarball, which has the side effect of
	# setting up the bind directory we will use for building
	# the libraries
	echo Creating tarball for $BINDTAG
	sh kit.sh --remote="git@$repo_host:$repo_path.git" $SNAP $BINDTAG $binddir
	. ./version.tmp

	version=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}
	bindsrcdir=bind-$version
	mm=${MAJORVER}.${MINORVER}

	# move the tar file to a known place for use by the make dist command
	echo Moving tar file to bind.tar.gz for distribution
	mv bind-${mm}*.tar.gz bind.tar.gz
fi
