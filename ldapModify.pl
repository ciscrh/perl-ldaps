#!/usr/bin/perl
# ldapModify.pl
#
# carry out a simple ldap modify operation on specified attributes of the given DNs
# ldap dn supplied as input param or text file containing one dn per line
# only one add, delete and/or replace option attribute can be specified
# consider using ldapModBatch.pl for non-trivial modifications
# v1.03 crh 14-feb-09 -- initial release, based on ldapSearch
# v1.12 crh 06-feb-10 -- defaults revamped, password processing improved
# v1.20 crh 29-apr-10 -- attribute value ### comma workaround added
# v1.35 crh 14-may-10 -- quiet switch added
# v1.41 crh 04-oct-10 -- refactored using crhArg and crhEntry
# v1.51 crh 24-oct-11 -- home version (underscore 2 space added)
# v1.60 crh 10-jul-12 -- reviewed (refactoring & file input param processing)

use warnings;
use strict;
use lib '../crhLib';	# crh custom packages
use Net::LDAP;
use Net::LDAPS;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhString;	# custom string subroutines
use crhArg;	# custom argument subroutines
use crhEntry;	# custom entry file subroutines
use crhFile;	# custom file subroutines

#### sanity checks

my $progName = "ldapModify";
my $debug = 0;	# optional param default value -- 1 = debug on, 0 = debug off
my %opts = ();
my $ldapHost = '127.0.0.1';	# optional param default value, works for me :-)
my $ldapPort = 636;	 # optional param
my $ldapSSL = 1;	# optional switch
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $ldapDN = "";	 # mandatory param
my $ldapDNF = ""; # alternative mandatory param
my $ldapAddAttr = "";	# optional param
my $throttleSec = 5;	# optional param default value -- how long to sleep
my $quiet = 0;	# optional param default value -- turn off some informational output
my $ldapDelAttr = "";	# optional param
my $ldapReplAttr = "";	# optional param
my @ldapAddVals = ();	# add attrib values
my @ldapDelVals = ();	# delete attrib values
my @ldapReplVals = ();	# delete attrib values
my $ldapModAction = "";
my $throttleBatch = 100; # how often to sleep
my $fMesg = "";

my $ldap;
my $fileH;

my $paramOK = 1;	# params check
my $modAction = 0;	# modify action check
my $modifyCount = 0;
my $lineCount = 0;
my $fieldCount = 0;
my $ignoreCount = 0;
my $failCount = 0;
my $ldapDnCount;
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

sub getAttribVals ($) {
# set attrib and values (processing input params)
# allows ### to be used to specify comma char within attrib value
# (comma is used as the value delimiter char when providing multiple attribute values)
# args: string list (attrib [val...])
# return attrib, [val...]

	my $val;
	my $idx;
	my @vals = split(/[ ,]/, $_[0]);	# space or comma separated
	my $attrib = $vals[0];
	if (@vals == 1) {	# only one element (the attrib)
		@vals = ();
	} else {
		foreach $idx (1..$#vals) {	# substitute comma for ###
			$val = $vals[$idx];
			$val =~ s/###/,/g;
			$vals[$idx] = $val;
		}
		@vals = @vals[1 .. $#vals];
	}
	return $attrib, @vals;
}

sub modify () {
# process ldapModify action
# all three actions can be processed as required

	my $ok = 1;	# return true if all mods ok

	if ($ldapDelAttr) {
		$ldapModAction = "delete";
		dbgMsg("delete: $ldapDelAttr -- @ldapDelVals");
		if (@ldapDelVals) {	# delete specified values
			ldapModify($ldap, $ldapDN, $ldapModAction, $ldapDelAttr, \@ldapDelVals);
		} else {	# delete all values
			ldapModify($ldap, $ldapDN, $ldapModAction, $ldapDelAttr);
		}
		if (ldapIsError()) {
			statusErrMsg("warn", "modify", "delete attribute failed: $ldapDN");
			$ok = 0;
			$ldapErrorCount++;
		}
	}
	if ($ldapReplAttr) {
		$ldapModAction = "replace";
		dbgMsg("replace: $ldapReplAttr -- @ldapReplVals");
		if (@ldapReplVals) {	# delete all existing values and replace with specified values
			ldapModify($ldap, $ldapDN, $ldapModAction, $ldapReplAttr, \@ldapReplVals);
		} else {	# delete all existing values
			ldapModify($ldap, $ldapDN, $ldapModAction, $ldapReplAttr);
		}
		if (ldapIsError()) {
			statusErrMsg("warn", "modify", "replace attribute failed: $ldapDN");
			$ok = 0;
			$ldapErrorCount++;
		}
	}
	if ($ldapAddAttr) {	# add specified values
		$ldapModAction = "add";
		dbgMsg("add: $ldapAddAttr -- @ldapAddVals");
		ldapModify($ldap, $ldapDN, $ldapModAction, $ldapAddAttr, \@ldapAddVals);
		if (ldapIsError()) {
			statusErrMsg("warn", "modify", "add attribute failed: $ldapDN");
			$ok = 0;
			$ldapErrorCount++;
		}
	}
	return $ok;
}

sub help {

	errMsg("$progName -- carry out ldap modify on supplied objects");
	errMsg("usage: $progName.pl -e _entryDN|-E _entryListFile -u _username [-p _pw][-h _host]");
	errMsg("         [-P _port][-t _sec][-q{uiet][-d{ebug][-i{nsecure]") if !$quiet;
	errMsg("         [-A _attrib[,_value...]][-D _attrib[,_value...]][-R _attrib[,_value...]]");
	errMsg("hints: multiple attribute values separated by commas");
	errMsg("       commas in values represented by ###");
	errMsg("       spaces in DNs and attribute values represented by __\n");
}

sub debugParam {
# output post parameter processing information if debug mode enabled

	errMsg("") if $debug;
	dbgMsg("host        = $ldapHost");
	dbgMsg("port        = $ldapPort");
	dbgMsg("user        = $ldapUser");
	if (argGetPw('p')) {
		dbgMsg("pw          = $ldapPw");
	} elsif ($ldapPw) {
		dbgMsg("pw          = supplied interactively");
	}
	dbgMsg("entry dn    = $ldapDN");
	dbgMsg("entry file  = $ldapDNF");
	dbgMsg("add attrib  = $ldapAddAttr");
	dbgMsg("add values  = @ldapAddVals");
	dbgMsg("del attrib  = $ldapDelAttr");
	dbgMsg("del values  = @ldapDelVals");
	dbgMsg("repl attrib = $ldapReplAttr");
	dbgMsg("repl values = @ldapReplVals");
	dbgMsg("throttle    = $throttleSec");
	dbgMsg("quiet mode  = " . trueFalse($quiet, "enabled", "disabled"));
	dbgMsg("ssl         = " . trueFalse($ldapSSL, "enabled (ldaps)\n", "disabled (ldap)\n"));
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

## process input params

argSetOpts('diqA:D:e:E:R:h:p:P:t:u:');

$quiet = argSetQuiet(argGetFlag('q'));
ldapSetQuiet($quiet);	# suppress LDAP error messages in quiet mode
$debug = setDbg(argGetFlag('d', 'debug mode enabled'));
help() if !$quiet;
dbgMsg("process command line switches...");

if (argGetParam('D')) {
	($ldapDelAttr, @ldapDelVals) = getAttribVals(argGetParam('D'));
	under2Space(@ldapDelVals);
	errMsg("ldap del attr: $ldapDelAttr") if !$quiet;
	errMsg("ldap del values: @ldapDelVals") if !$quiet;
	$modAction = 1;
}
if (argGetParam('R')) {
	($ldapReplAttr, @ldapReplVals) = getAttribVals(argGetParam('R'));
	under2Space(@ldapReplVals);
	errMsg("ldap repl attr: $ldapReplAttr") if !$quiet;
	errMsg("ldap repl values: @ldapReplVals") if !$quiet;
	$modAction = 1;
}
if (argGetParam('A')) {
	($ldapAddAttr, @ldapAddVals) = getAttribVals(argGetParam('A'));
	under2Space(@ldapAddVals);
	errMsg("ldap add attr: $ldapAddAttr") if !$quiet;
	errMsg("ldap add values: @ldapAddVals") if !$quiet;
	$modAction = 1;
	if (!scalar(@ldapAddVals)) {	# no values provided
		statusErrMsg("fatal", "inputParams", "abort program: add attribute values missing");
		$paramOK = 0;
	}
}
if (argGetParam('h')) {
	$ldapHost = argGetParam('h', 'ldap host: ');
}
if (argGetParam('P')) {
	$ldapPort = argGetParam('P', 'host ldap port: ');
}
if (argGetParam('t')) {
	$throttleSec = argGetParam('t', 'throttle sleep time: ');
}
if (argGetFlag('i', 'insecure ldap enabled')) {
	$ldapSSL = 0;
	if (!argGetParam('P')) {	# change default port
		$ldapPort = 389;
		errMsg("[host ldap port: $ldapPort]") if !$quiet;
	}
}
if (argGetParam('e')) {
	$ldapDN = argGetParam('e');
	under2Space($ldapDN);
	if (argGetParam('E')) {
		statusErrMsg("warn", "inputParams", "entry dn parameter ignored");
	} else {
		errMsg("ldap dn: $ldapDN") if !$quiet;
	}
} elsif (!argGetParam('E')) {
	statusErrMsg("fatal", "inputParams","abort program: no dn provided");
	$paramOK = 0;
}
if (argGetParam('E')) {
	$ldapDNF = argGetInputFile ('E', "entry file: ", "no entry file provided");
	if (!$ldapDNF) {
		statusErrMsg("fatal", "inputParams", "abort program: input file problem");
		$paramOK = 0;
	} else {
	$ldapDNF = absPath(dos2UnixPath($ldapDNF));
	}
}
if (argGetParam('u')) {
	$ldapUser = argGetParam('u');
	under2Space($ldapUser);
	errMsg("authentication user dn: $ldapUser") if !$quiet;
} else {
	statusErrMsg("fatal", "inputParams","abort program: no authentication username provided");
	$paramOK = 0;
}
if ($paramOK) {
	$ldapPw = argGetPw('p', "password supplied", "no password supplied...", "enter password: ");
} elsif (argGetPw('p')) {
	$ldapPw = argGetPw('p', "password supplied");
}
if (!$modAction) {
	statusErrMsg("fatal","inputParams", "abort program: no modify action specified");
	$paramOK = 0;
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
	statusErrMsg("fatal","ldapBind","abort program: ldap bind failed");
	die "\n";
}

## process modify operations

if ($ldapDNF) {
	if (open $fileH, $ldapDNF) {	# process entry file (takes precedence)
		dbgMsg("file: $ldapDNF");
		errMsg("processing dn file...");
		while ($ldapDN = <$fileH>) {
			$lineCount++;
			chomp($ldapDN);
			$ldapDN = trim($ldapDN);	# trim whitespace
			if (entryIsBlank($ldapDN) || entryIsMode($ldapDN) || entryIsMoveRename($ldapDN)) {
				# ignore blank, comment (#) and changemode lines
				$ignoreCount++;
				dbgMsg("ignore>>$ldapDN");
				next;
			} elsif (!entryHasColon($ldapDN)) {	# basic check for colon character
				$failCount++;
				dbgMsg("fail>>$ldapDN");
				next;
			}
			$fieldCount++;
			if (!entryIsDN($ldapDN)) {
				$ignoreCount++;
				dbgMsg("ignore>>$ldapDN");
				next;
			} else {
			$ldapDnCount++;
			msg("modify $ldapDN") if !$quiet;
			$ldapDN = entryGetDN($ldapDN);
			$modifyCount++ if modify();
			if ($throttleSec && $modifyCount && !($modifyCount % $throttleBatch)) {
				errTMsg("pausing for $throttleSec seconds ($modifyCount)...");
				sleep($throttleSec);
				}
			}
		}
		close($fileH);
	} else {
		statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening dn file");
		die "\n";
	}
} else {	# process input param entry dn
	msg("modify $ldapDN") if !$quiet;
	$modifyCount++ if modify();
}

## tidy up

$ldap->unbind;   # take down session

errMsg("");
if ($ldapDNF ne "") {
	if (!$quiet) {
		errMsg(singural($lineCount, " line", " lines") . " read from file");
		errMsg(singural($ignoreCount, " line", " lines") . " ignored") if $ignoreCount;
		errMsg(singural($failCount, " unknown line", " unknown lines") . " ignored") if $failCount;
		errMsg(singural($fieldCount, " data line", " data lines") . " processed");
	}
	errMsg(singural($ldapDnCount, " dn line", " dn lines") . " identified") if !$quiet;
}
errMsg(singural($modifyCount, " entry", " entries") . " processed") if ($ldapDNF);
errMsg(singural($ldapErrorCount, " ldap error", " ldap errors") . " reported") if $ldapErrorCount;
errTMsg("...$progName exits normally") if !$quiet;

#### end of main
