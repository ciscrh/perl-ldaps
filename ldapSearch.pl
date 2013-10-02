#!/usr/bin/perl
# ldapSearch.pl
#
# carry out an ldap search, outputting DNs and specified attributes of the matching entries
# ldap filter supplied as input param or text file containing one filter per line
# v1.05 crh 10-feb-09 -- initial release, based on ldapSearchDN
# v1.10 crh 03-mar-09 -- quiet switch added
# v1.25 crh 05-feb-10 -- defaults revamped, password processing improved & anon binds accepted
# v1.32 crh 01-may-10 -- paged ldap search queries supported (specifically for AD)
# v1.42 crh 02-oct-10 -- refactored using crhArg (note: crhEntry not used by this script)
# v1.51 crh 22-sep-11 -- home version (underscore 2 space added)
# v1.60 crh 10-jul-12 -- reviewed (refactoring & file input param processing)

use warnings;
use strict;
use lib '../crhLib';	# crh custom packages location
use Net::LDAP;
use Net::LDAPS;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhString;	# custom string subroutines
use crhArg;	# custom argument subroutines
use crhFile;	# custom file subroutines

#### sanity checks

my $progName = "ldapSearch";
my $debug = 0;	# optional param default value -- 1 = debug on, 0 = debug off
my $ldapHost = '127.0.0.1';	# optional param default value, works for me :-)
my $ldapPort = 636;	 # optional param default value
my $ldapSSL = 1;	# optional switch default value
my $ldapUser="";	# mandatory param (well, anon bind assumed if not provided)
my $ldapPw = "";	# optional param
my $ldapScope = "sub";	# optional param default value
my $ldapBase = "o=hailey";	# optional param default value, works for me :-)
my $ldapFilter = "";	 # mandatory param
my $ldapFilterF = ""; # alternative mandatory param
my $ldapLimit = 1000;	# optional param default value
my $ldapTtlOnly = 0;	# optional param default value
my $ldapAttribs = "";	# optional param default value
my @ldapAttribs = ['1.1'];	# return no attribs
my $ldapPageSize = 0;	# optional param default value -- 0 = paged search disabled
my $throttleBatch = 100; #  -- how often to sleep
my $throttleSec = 1;	# optional param default value -- how long to sleep
my $quiet = 0;	# optional param default value -- turn off some informational output
my $fMesg = "";

my $ldap;
my $mesg;
my @entries;
my $entry;
my $fileH;
my @entryAttribs;
my $entryAttrib;
my @entryValues;
my $entryValue;
my $lineCount = 0;
my $filterCount = 0;
my $ignoreCount = 0;
my $unknownCount = 0;
my $ldapErrorCount = 0;
my $searchTtl = 0;
my $paramOK = 1;	# params check

#### subroutines

sub under2Space (@) {	# converts __ to space
# converts double underscores to single spaces
# allows dn and attribute values with embedded spaces to be given in parameters
# not needed or used for ldap entry file values
# args: array of values (accepts single value)
# probably not needed -- place values in quotation marks :-)

	my $val;
	my $index = 0;

	foreach $val (@_) {
		$val =~ s/__/ /g;
		$_[$index++] = $val;
	}
}

sub isBlankComment($) {
# tests for blank or comment lines
# args: line
# return 1 if true, 0 otherwise

	if (($_[0] =~ m/^#/)||(!length($_[0]))) {	# blank or starts with #
		$ignoreCount++;
		dbgMsg("ignore>>$_[0]");
		return 1;
	} else {
		return 0;
	}
}

sub isNotFilter($) {
# tests for equal sign character in required position
# args: line
# return 1 if true, 0 otherwise

	if (($_[0] =~ m/[^=]+=.+/)) {	# some_char(s)=some_char(s)
		return 0;
	} else {
		$unknownCount++;
		dbgMsg("unknown>>$_[0]");
		return 1;
	}
}

sub msgEntry ($) {
# formatted printing of entry to STDOUT
# warning: it uses pretty strings to handle the display of binary data
# args: entry

	if ($ldapAttribs ne "") {	# dn + attribs
		msg("");
	}
	msg("dn: " . $_[0]->dn());
	@entryAttribs = $_[0]->attributes();
	foreach $entryAttrib (@entryAttribs) {
		@entryValues = $_[0]->get_value($entryAttrib);
		foreach $entryValue (@entryValues) {
			msg("  $entryAttrib: " . pretty($entryValue));
		}
	}
}

sub help {

	errMsg("$progName: carry out ldap search, returning details of the matching objects");
	errMsg("usage: $progName.pl -f _filter|-F _filterFile [-u _username][-p _pw][-h _host]");
	errMsg("         [-b _base][-s _scope][-a _csvAttribs][-l _limit][-P _port]");
	errMsg("         [-T _sec][-S _pageSize][-t{otalOnly}][-q{uiet}][-d{ebug}][-i{nsecure}]");
	errMsg("hints: direct output to file to use as entry file input to other scripts");
	errMsg("       use * to specify all and + for additional operational attributes");
	errMsg("       spaces in filter values represented by __");
	errMsg("       specify a page size for AD queries to ensure all entries output\n");
}

sub debugParam {
# output post parameter processing information if debug mode enabled

	errMsg("") if $debug;
	dbgMsg("host       = $ldapHost");
	dbgMsg("port       = $ldapPort");
	dbgMsg("user       = " . trueFalse($ldapUser, $ldapUser, "anonymous"));
	if (argGetPw('p') || $ldapPw eq "anonymous") {
		dbgMsg("pw         = $ldapPw");
	} elsif ($ldapPw) {
		dbgMsg("pw         = supplied interactively");
	}
	dbgMsg("filter     = $ldapFilter");
	dbgMsg("file       = $ldapFilterF");
	dbgMsg("base       = $ldapBase");
	dbgMsg("scope      = $ldapScope");
	dbgMsg("attribs    = $ldapAttribs");
	dbgMsg("limit      = $ldapLimit");
	dbgMsg("page size  = $ldapPageSize");
	dbgMsg("throttle   = $throttleSec");
	dbgMsg("quiet mode = " . trueFalse($quiet, "enabled", "disabled"));
	dbgMsg("total only = " . trueFalse($ldapTtlOnly, "enabled", "disabled"));
	dbgMsg("ssl        = " . trueFalse($ldapSSL, "enabled (ldaps)\n", "disabled (ldap)\n"));
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

## process input params

argSetOpts('diqta:b:f:F:h:l:p:P:s:S:T:u:');

$quiet = argSetQuiet(argGetFlag('q'));
ldapSetQuiet($quiet);	# suppress LDAP error messages in quiet mode
$debug = setDbg(argGetFlag('d', 'debug mode enabled'));
help() if !$quiet;
dbgMsg("process command line switches...");

if (argGetParam('h')) {
	$ldapHost = argGetParam('h', 'ldap host: ');
} else {
	errMsg("default ldap host: $ldapHost") if !$quiet;
}
if (argGetParam('b')) {
	$ldapBase = argGetParam('b');
	under2Space($ldapBase);
	errMsg("ldap search base: $ldapBase") if !$quiet;
} else {
	errMsg("default ldap search base: $ldapBase") if !$quiet;
}
if (argGetFlag('i', 'insecure ldap enabled')) {
	$ldapSSL = 0;
	if (!argGetParam('P')) {	# change default port
		$ldapPort = 389;
		errMsg("[ldap port: $ldapPort]") if !$quiet;
	}
} else {
	errMsg("default mode: secure (ldaps)") if !$quiet;
}
if (argGetParam('s')) {
	$ldapScope = lc(argGetParam('s', 'ldap search scope: '));
	if ($ldapScope !~ m/^(one|base|sub)$/) {
		statusErrMsg("fatal", "inputParams", "abort program: illegal search scope (one|base|sub)");
		$paramOK = 0;
	}
} else {
	errMsg("default scope: $ldapScope") if !$quiet;
}
if (argGetParam('a')) {
	$ldapAttribs = argGetParam('a', 'ldap attributes: ');
	@ldapAttribs = split(/[ ,]/, $ldapAttribs);
	under2Space(@ldapAttribs);
}
if (argGetParam('P')) {
	$ldapPort = argGetParam('P', 'ldap port: ');
}
if (argGetParam('S')) {
	$ldapPageSize = argGetParam('S', 'ldap page size: ');
}
if (argGetParam('T')) {
	$throttleSec = argGetParam('T', 'throttle sleep time: ');
}
if (argGetParam('l') eq "0") {	# special case of zero meaning no limit
	$ldapLimit = 0;
	errMsg("ldap search limit: $ldapLimit [no limit]") if !$quiet;
} elsif (argGetParam('l')) {	# process all other values
	$ldapLimit = argGetParam('l', 'ldap search limit: ')
}
if (argGetFlag('t', 'total only enabled')) {
	$ldapTtlOnly = 1;
}
if (argGetParam('u')) {
	$ldapUser = argGetParam('u');
	under2Space($ldapUser);
	errMsg("authentication user dn: $ldapUser") if !$quiet;
} else {
	statusErrMsg("info", "inputParams","anonymous bind: no username provided");
}
if (argGetParam('f')) {
	$ldapFilter = argGetParam('f');
	under2Space($ldapFilter);
	if (argGetParam('F')) {
		statusErrMsg("warn", "inputParams", "filter parameter ignored");
	} else {
		errMsg("ldap filter: $ldapFilter") if !$quiet;
	}
} elsif (!argGetParam('F')) {
	statusErrMsg("fatal", "inputParams","abort program: no search filter provided");
	$paramOK = 0;
}
if (argGetParam('F')) {
	$ldapFilterF = argGetInputFile ('F', "filter file: ", "no filter file provided");
	if (!$ldapFilterF) {
		statusErrMsg("fatal", "inputParams", "abort program: input file problem");
		$paramOK = 0;
	} else {
		$ldapFilterF = absPath(dos2UnixPath($ldapFilterF));
	}
}
if ($paramOK && $ldapUser eq "") {	# anonymous bind assumed
	$ldapPw = "anonymous";
} elsif ($paramOK) {
	$ldapPw = argGetPw('p', "password supplied", "no password supplied...", "enter password: ");
} elsif (argGetPw('p')) {
	$ldapPw = argGetPw('p', "password supplied");
}

debugParam();
if (!$paramOK) {
	die "\n";
}

## make ldap connection

errTMsg("connect to $ldapHost:$ldapPort as $ldapUser ...") if !$quiet;
if ($ldapSSL) {	# secure connection
	$ldap = ldapsNew($ldapHost, $ldapPort);
} else {	# insecure connection
	$ldap = ldapNew($ldapHost, $ldapPort);
}

$mesg = ldapBind($ldap, $ldapUser, $ldapPw);	# ldap bind
if (ldapIsError()) {
	statusErrMsg("fatal","ldapBind", "abort program: ldap bind failed");
	die "\n";
}

## carry out search and output DNs and attributes to STDOUT

if ($ldapFilterF) {
	if (open $fileH, $ldapFilterF) {	# process file (takes precedence)
		errMsg("processing filter file...");
		while ($ldapFilter = <$fileH>) {
			chomp($ldapFilter);
			$lineCount++;
			$ldapFilter = trim($ldapFilter);	# trim whitespace
			if (isBlankComment($ldapFilter)) {
				next;
			} elsif (isNotFilter($ldapFilter)) {
				next;
			} else {
				dbgMsg("filter: $ldapFilter");
			}
			$filterCount++;
			if ($ldapPageSize) {	# paged ldap search
				@entries = ldapSearchPaged($ldap, $ldapBase, $ldapScope, $ldapFilter, $ldapPageSize, \@ldapAttribs, $ldapLimit);
				$searchTtl += scalar(@entries);
				foreach $entry (@entries) {
					msgEntry($entry);
				}
			} else {
				$mesg = ldapSearch($ldap, $ldapBase, $ldapScope, $ldapFilter, \@ldapAttribs, $ldapLimit);
				if (ldapIsError()) {
					statusErrMsg("warn", "processFile", "search failed: $ldapFilter");
					$ldapErrorCount++;
				} else {
					$searchTtl += $mesg->count;
					foreach $entry ($mesg->entries) {
						msgEntry($entry);
					}
				}
			}
			if ($throttleSec && !($filterCount % $throttleBatch)) {
				errTMsg("pausing for " . singural($throttleSec, " second", " seconds") .
				" ($searchTtl in $filterCount)...");
				sleep($throttleSec);
			}
		}
		close($fileH);
	} else {
		statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening filter file");
		die "\n";
	}
} else {	# process input param filter
	if ($ldapPageSize) {	# paged ldap search
		@entries = ldapSearchPaged($ldap, $ldapBase, $ldapScope, $ldapFilter, $ldapPageSize, \@ldapAttribs, $ldapLimit);
		if (ldapIsError()) {
			statusErrMsg("warn", "processParam", "search failed: $ldapFilter");
			$ldapErrorCount++;
		} else {
			$searchTtl = scalar(@entries);
		}
	} else {
		$mesg = ldapSearch($ldap, $ldapBase, $ldapScope, $ldapFilter, \@ldapAttribs, $ldapLimit);
		if (ldapIsError()) {
			statusErrMsg("warn", "processParam", "search failed: $ldapFilter");
			$ldapErrorCount++;
		} else {
			$searchTtl = $mesg->count;
		}
	}
	errMsg("nr of hits: $searchTtl") if !$quiet;
	if ($searchTtl == $ldapLimit) {
		if ($searchTtl == 1000) {
			statusErrMsg("warn", "sizeLimit", "default search limit ($ldapLimit) reached");
		} elsif ($ldapLimit > 0) {
			statusErrMsg("info", "sizeLimit", "search limit ($ldapLimit) reached");
		}
	}

	if(!$ldapTtlOnly) {
		if ($ldapPageSize) {	# paged ldap search
			foreach $entry (@entries) {
				msgEntry($entry);
			}
		} else {
			foreach $entry ($mesg->entries) {
				msgEntry($entry);
			}
		}
	}
}

## tidy up

$ldap->unbind;   # take down session

errMsg("");
if ($ldapFilterF ne "") {
	errMsg(singural($lineCount, " line", " lines") . " read from file");
	errMsg(singural($ignoreCount, " line", " lines") . " ignored") if $ignoreCount;
	errMsg(singural($unknownCount, " invalid line", " invalid lines") . " skipped") if $unknownCount;
	errMsg(singural($filterCount, " filter line", " filter lines") . " processed");
}
msg('# ' . singural($searchTtl, " record matches", " records match") . " search criteria");
errMsg(singural($ldapErrorCount, " ldap error", " ldap errors") . " reported") if $ldapErrorCount;
errTMsg("$progName exits normally") if !$quiet;

#### end of main
