#!/usr/bin/perl
#
# Makefile.PL for Config::Access module
#
# $Id: Makefile.PL,v 1.2 1998/08/31 02:10:22 tpot Exp $
#

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME' => "Config::Access",
    'DISTNAME' => "Config-Access",
    'VERSION' => "0.01",
    'dist' => {
	'COMPRESS' => "gzip -9f",
	'SUFFIX' => "gz"
	}
);
