#!/usr/bin/perl
#
# Makefile.PL for Config::Access module
#
# $Id: Makefile.PL,v 1.3 1998/09/18 03:07:37 tpot Exp $
#

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => "Config::Access",
    DISTNAME => "Config-Access",
    VERSION_FROM => "Access.pm",
    dist => {
	'COMPRESS' => "gzip -9f",
	'SUFFIX' => "gz"
	}
);
