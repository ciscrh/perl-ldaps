#!/usr/bin/perl
# ldapAdd.pl
#
# carry out an ldap add operation using specified dn and attributes
# dn and attributes supplied as ldap entry file containing DNs and attribs
# v1.01 crh 18-feb-09 -- does not use Net::LDAP::Entry, which doesn't work in all distributions
# v1.10 crh 07-feb-10 -- defaults revamped, password processing improved
# v1.20 crh 03-may-10 -- attribute value ### comma workaround added
# v1.32 crh 14-may-10 -- quiet switch added
# v1.42 crh 30-sep-10 -- crhEntry, crhArg refactoring
# v1.51 crh 10-oct-11 -- home version (underscore 2 space added)
# v1.60 crh 09-jul-12 -- reviewed (refactoring & file input param processing)

use warnings;
use strict;
use lib '../crhLib';	# crh custom packages
use Net::LDAP;
use Net::LDAPS;
use Getopt::Std;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhFile;	# custom file subroutines
use crhString;	# custom string subroutines
use crhArg;	# custom argument subroutines
use crhEntry;	# custom entry file subroutines

#### sanity checks

my $progName = "ldapAdd";
my $debug = 0;	# optional param default value -- 1 -> debug on, 0 -> debug off
my $ldapHost = '127.0.0.1';	# optional param default value, works for me :-)
my $ldapPort = 636;	 # optional param default value
my $ldapSSL = 1;	# optional param default value
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $ldapEntryF = ""; # mandatory ldap entry file param
my $ldapDN = "";	# added object dn
my %ldapAttribs = ();	# added object attributes array
my $throttleBatch = 100; # how often to sleep
my $throttleSec = 2;	# optional param default value -- how long to sleep
my $quiet = 0;	# optional param default value -- turn off some informational output
my $fMesg = "";

my $ldap;
my @createAttribs = ();
my $fileH;
my $fileLine;
my $entryCount = 0;
my $lineCount = 0;
my $fieldCount = 0;
my $paramOK = 1;	# params check
my $lastDN = 0;
my $ldapDnCount = 0;
my $ignoreCount = 0;
my $failCount = 0;
my $ldapErrorCount = 0;

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

sub processFileAttrib {
# process single attrib line from input file
# allows ### to be used to specify comma char in attrib value
# args: attrib line (in format name:value), ref to hash of name keys and strings of values
# modifies referenced hash directly, no need to return anything
# complicated by the fact that the values may contain colons
# detects and ignores embedded change mode command lines

	my $attribRef = $_[1];	# ref to hash
	my $name = $_[0];
	my $value = $_[0];

	$name =~ s/:.+//;	# text up to first colon
	$name = trim($name);
	$value =~ s/^[^:]+://;	# text after first colon
	$value = trim($value);
	$value =~ s/###/,/g;	# substitute comma for ###
	if ($name =~ m/changemode/i) {	# change mode command
		statusErrMsg("warn", "processFileAttrib", "$value change mode command ignored");
		return;
	}
	if (exists($attribRef->{$name})) {	# extend list string
		$attribRef->{$name} = $attribRef->{$name} . ":##:" . $value;
	} else {	# add single element list string
		$attribRef->{$name} = $value;
	}
}

sub setAddArray {
# args: ref to attribs hash
# returns array of attributes for ldapAdd()

	my $attribsRef = $_[0];
	my @createAttrs;
	my $name;
	my $valueList;
	my @values;

	foreach $name (keys %$attribsRef) {
		$valueList = $attribsRef->{$name};
		dbgMsg($name . ": $valueList");
		if ($valueList =~ m/:##:/) {	# list
			@values = split(/:##:/, $valueList);
			push(@createAttrs, $name => [@values]);
		} else {	# single value
			push(@createAttrs, $name => $valueList);
		}
	}
	if ($debug) {
		for (my $index = 0; $index <@createAttrs; $index++) {
			dbgMsg("createAttrs[$index]>>>>" . $createAttrs[$index]);
		}
	}
	return @createAttrs;
}

sub help {

errMsg("$progName -- carry out ldap add using dn and attributes supplied in entry file");
errMsg("usage: $progName.pl -E _entryFile  -u _username [-p _pw][-h _host]");
errMsg("         [-P _port][-T _sec][-q{uiet}][-i{nsecure}][-d{ebug}]\n");
}

sub debugParam {
# output post parameter processing information if debug mode enabled

	errMsg("") if $debug;
	dbgMsg("host       = $ldapHost");
	dbgMsg("port       = $ldapPort");
	dbgMsg("user       = $ldapUser");
	if (argGetPw('p')) {
		dbgMsg("pw         = $ldapPw");
	} elsif ($ldapPw) {
		dbgMsg("pw         = supplied interactively");
	}
	dbgMsg("file       = $ldapEntryF");
	dbgMsg("throttle   = $throttleSec");
	dbgMsg("quiet mode = " . trueFalse($quiet, "enabled", "disabled"));
	dbgMsg("ssl        = " . trueFalse($ldapSSL, "enabled (ldaps)\n", "disabled (ldap)\n"));
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");


## process input params
argSetOpts('diqE:h:p:P:T:u:');

$quiet = argSetQuiet(argGetFlag('q'));
ldapSetQuiet($quiet);	# suppress LDAP error messages in quiet mode
entrySetQuiet($quiet);	# suppress entry error messages in quiet mode
$debug = setDbg(argGetFlag('d', 'debug mode enabled'));
help() if !$quiet;
dbgMsg("process command line switches...");

if (argGetParam('h')) {
	$ldapHost = argGetParam('h', 'ldap host: ');
}
if (argGetParam('P')) {
	$ldapPort = argGetParam('P', 'ldap port: ');
}
if (argGetParam('T')) {
	$throttleSec = argGetParam('T', 'throttle sleep time: ');
}
if (argGetFlag('i', 'insecure ldap enabled')) {
	$ldapSSL = 0;
	if (!argGetParam('P')) {	# change default port
		$ldapPort = 389;
		errMsg("[host ldap port: $ldapPort]") if !$quiet;
	}
}
$ldapEntryF = argGetInputFile ('E', "entry file: ", "no entry file provided");
if (!$ldapEntryF) {
	statusErrMsg("fatal", "inputParams", "abort program: entry file problem");
	$paramOK = 0;
} else {
	$ldapEntryF = absPath(dos2UnixPath($ldapEntryF));
}
if (argGetParam('u')) {
	$ldapUser = argGetParam('u', 'authentication user dn: ');
	under2Space($ldapUser);
} else {
	statusErrMsg("fatal", "inputParams", "abort program: no authentication user provided");
	$paramOK = 0;
}
if ($paramOK) {
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

ldapBind($ldap, $ldapUser, $ldapPw);	# ldap bind
if (ldapIsError()) {
	statusErrMsg("fatal","ldapBind", "abort program: ldap bind failed");
	die "\n";
}

## process add operations

if (open $fileH, $ldapEntryF) {
	errMsg("processing entry data file $ldapEntryF...");
	while ($fileLine = <$fileH>) {
		chomp($fileLine);
		$lineCount++;
		$fileLine = trim($fileLine);	# trim whitespace
		if (entryIsBlank($fileLine) || entryIsMode($fileLine) || entryIsMoveRename($fileLine)) {
			# ignore blank, comment (#) and changemode lines
			$ignoreCount++;
			dbgMsg("ignore>>$fileLine");
			next;
		} elsif (!entryIsValidLine($fileLine)) {	# basic syntax check
			$failCount++;
			next;
		} else {
			$fieldCount++;
		}
		if (entryIsDN($fileLine)) {	# start of entry (dn:)
			$ldapDnCount++;
			if ($lastDN) {	# process previous dn data
				$ldapDN = $lastDN;
				@createAttribs = setAddArray(\%ldapAttribs);
				ldapAdd($ldap, $ldapDN, \@createAttribs);
				if (ldapIsError()) {
					statusErrMsg("warn", "processFile", "add failed: $ldapDN");
					++$ldapErrorCount;
				} else {
					msg("add: $ldapDN");
					if ($throttleSec && !(++$entryCount % $throttleBatch)) {
						errTMsg("pausing for $throttleSec seconds ($entryCount)...");
						sleep($throttleSec);
					}
				}
			}
			$lastDN = entryGetDN($fileLine);
			dbgMsg("dn>>$lastDN");
			$ldapDN = 0;
			@createAttribs = ();
			%ldapAttribs = ();
		} elsif ($lastDN) {	# process attribute
					processFileAttrib($fileLine, \%ldapAttribs);
		}
	}
	close($fileH);
	if ($lastDN) {
		@createAttribs = setAddArray(\%ldapAttribs);
		ldapAdd($ldap, $lastDN, \@createAttribs);
		if (ldapIsError()) {
			statusErrMsg("warn", "processFile", "add failed: $lastDN");
			++$ldapErrorCount;
		} else {
			msg("add: $lastDN");
			$entryCount++;
		}
	}
} else {
	statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening entry file");
	die "\n";
}

## tidy up
$ldap->unbind;   # take down session
errMsg("");
if (!$quiet) {
	errMsg(singural($lineCount, " line", " lines") . " read from file");
	errMsg(singural($ignoreCount, " line", " lines") . " ignored") if $ignoreCount;
	errMsg(singural($failCount, " unknown line", " unknown lines") . " skipped") if $failCount;
	errMsg(singural($fieldCount, " data line", " data lines") . " processed");
	errMsg(singural($ldapDnCount, " dn line", " dn lines") . " identified");
}
errMsg(singural($entryCount, " entry", " entries") . " added to directory");
errMsg(singural($ldapErrorCount, " ldap error", " ldap errors") . " reported") if $ldapErrorCount;
errTMsg("...$progName exits normally") if !$quiet;

#### end of main
