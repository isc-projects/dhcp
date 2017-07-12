#!/usr/bin/perl
#
# Copyright (C) 2016-2017  Internet Systems Consortium, Inc. ("ISC")
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

# build configure.am with or without libtool stuff

require 5.000;
use strict;

# general arguments

my @optionlist = ("with", "without", "verbose");

# usage

my $usage = ("Usage: perl lt.pl [with|without] [verbose]\n");

# Parse arguments

my $with = 0;
my $verbose = 0;

foreach (@ARGV) {
    if (/^with$/i) {
	$with = 1;
    } elsif (/^without$/i) {
	$with = 0;
    } elsif (/^verbose$/i) {
	$verbose = 1;
    } else {
	die $usage;
    }
}

if ($verbose) {
    if ($with) {
	print STDERR "building the with libtool version\n";
    } else {
	print STDERR "building the without libtool version\n";
    }
}

# Perform 

my $line;
my $state = "top";
my $directives = 0;
my $included = 0;
my $escaped = 0;

foreach $line (<STDIN>) {
    chomp $line;
    if ($line =~ /^\@BEGIN WITH LIBTOOL$/) {
	if ($state eq "top") {
	    $state = "with";
	} elsif ($state eq "with") {
	    die "got WITH begin in WITH context\n";
	} elsif ($state eq "without") {
	    die "got WITH begin in WITHOUT context\n";
	}
	$directives += 1;
	next;
    } elsif ($line =~ /^\@BEGIN WITHOUT LIBTOOL$/) {
	if ($state eq "top") {
	    $state = "without";
	} elsif ($state eq "with") {
	    die "got WITHOUT begin in WITH context\n";
	} elsif ($state eq "without") {
	    die "got WITHOUT begin in WITHOUT context\n";
	}
	$directives += 1;
	next;
    } elsif ($line =~ /^\@END WITH LIBTOOL$/) {
	if ($state eq "with") {
	    $state = "top";
	} elsif ($state eq "top") {
	    die "got WITH end outside context\n";
	} elsif ($state eq "without") {
	    die "got WITH end in WITHOUT context\n";
	}
	$directives += 1;
	next;
    } elsif ($line =~ /^\@END WITHOUT LIBTOOL$/) {
	if ($state eq "without") {
	    $state = "top";
	} elsif ($state eq "top") {
	    die "got WITHOUT end outside context\n";
	} elsif ($state eq "with") {
	    die "got WITHOUT end in WITH context\n";
	}
	$directives += 1;
	next;
    } elsif ($line =~ /^@/) {
	die "git unknown directive '$line'\n";
    }

    if ($state eq "with") {
	if ($with) {
	    $included += 1;
	} else {
	    $escaped += 1;
	    next;
	}
    } elsif ($state eq "without") {
	if ($with) {
	    $escaped += 1;
	    next;
	} else {
	    $included += 1;
	}
    }
    print $line. "\n";
}

if ($verbose) {
    print STDERR "directives: $directives\n";
    print STDERR "included: $included\n";
    print STDERR "escaped: $escaped\n";
}

exit 0;
