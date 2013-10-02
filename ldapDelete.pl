#!/usr/bin/perl
# ldapDelete.pl
#
# carry out an ldap delete operation using specified dn
# dn supplied as input param or text file containing list of DNs
# v1.01 crh 16-feb-09 -- initial release, based on ldapAdd
# v1.10 crh 07-feb-10 -- defaults revamped, password processing improved
# v1.22 crh 14-may-10 -- quiet switch added
# v1.32 crh 03-oct-10 -- refactored using crhArg and crhEntry
# v1.41 crh 23-oct-11 -- home version (underscore 2 space added)
# v1.50 crh 08-jul-12 -- reviewed (refactoring & file input param processing)
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

my $progName = "ldapDelete";
my $debug = 0;	# optional param default value -- 1 = debug on, 0 = debug off
my %opts = ();
my $ldapHost = '127.0.0.1';	# optional param default value, works for me :-)
my $ldapPort = 636;	 # optional param default value
my $ldapSSL = 1;	# optional switch default value
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $ldapDN = "";	 # mandatory param
my $ldapDNF = ""; # alternative single mandatory param
my %ldapAttribs = ();
my $throttleBatch = 100; #  -- how often to sleep
my $throttleSec = 5;	# optional param -- how long to sleep
my $quiet = 0;	# optional param default value -- turn off some informational output
my $fMesg = "";

my $ldap;
my $fileH;
my $fileLine;
my $deleteCount = 0;
my $lineCount = 0;
my $fieldCount = 0;
my $ldapDnCount = 0;
my $ignoreCount = 0;
my $failCount = 0;
my $ldapErrorCount = 0;
my $paramOK = 1;	# params check

#### subroutines

sub under2Space (@) {# converts __ to space
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

sub help () {
# output help text unless quiet mode enabled

	errMsg("$progName -- carry out ldap delete of supplied DNs");
	errMsg("usage: $progName.pl -e _dn|-E _entryFile  -u _username [-p _pw][-h _host][-P _port]");
	errMsg("         [-t _sec][-i{nsecure}][-q{uiet}][-d{ebug}]");
	errMsg("hints: use __ to specify space character in parameter dn value");
	errMsg("         (workaround not needed in entry file dn values)\n");
}

sub debugParam () {
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
	dbgMsg("dn         = $ldapDN");
	dbgMsg("file       = $ldapDNF");
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

argSetOpts('diqe:E:h:p:P:t:u:');

$quiet = argSetQuiet(argGetFlag('q'));
ldapSetQuiet($quiet);	# suppress LDAP error messages in quiet mode
entrySetQuiet($quiet);	# suppress entry error messages in quiet mode
$debug = setDbg(argGetFlag('d', 'debug mode enabled'));
help();
dbgMsg("process command line switches...");

if (argGetParam('h')) {
	$ldapHost = argGetParam('h', 'ldap host: ');
} else {
	errMsg("default ldap host: $ldapHost") if !$quiet;
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
if (argGetParam('e') && (!argGetParam('E'))) {
	$ldapDN = argGetParam('e');
	under2Space($ldapDN);
	errMsg("delete object dn: $ldapDN") if !$quiet;
} elsif (!argGetParam('E')) {
	statusErrMsg("fatal", "inputParams", "abort program: no dn or entry file provided");
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
	statusErrMsg("fatal", "inputParams", "abort program: no authentication username provided");
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
	statusErrMsg("fatal", "ldapBind", "abort program: ldap bind failed");
	die "\n";
}

## process delete operations

if ($ldapDNF) {	# process entry file, if supplied (takes precedence)
	if (open $fileH, $ldapDNF) {
		errMsg("processing dn file $ldapDNF...");
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
				dbgMsg("fail>>$fileLine");
				next;
			}
			$fieldCount++;
			if (!entryIsDN($fileLine)) {
				dbgMsg("ignore>>$fileLine");
				next;
			}
			$ldapDnCount++;
			$fileLine = entryGetDN($fileLine);
			ldapDelete($ldap, $fileLine);
			if (ldapIsError()) {
				statusErrMsg("warn", "processFile", "delete failed: $fileLine");
				$ldapErrorCount++;
			} else {
				msg("delete: $fileLine");
				if ($throttleSec && !(++$deleteCount % $throttleBatch)) {
					errTMsg("pausing for $throttleSec seconds ($deleteCount)...");
					sleep($throttleSec);
				}
			}
		}
		close($fileH);
	} else {
		statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening entry file");
		die "\n";
	}
} else {	# process entry dn param if no input file
	ldapDelete($ldap, $ldapDN);
	if (ldapIsError()) {
		statusErrMsg("warn", "processInput", "delete failed: $ldapDN");
		$ldapErrorCount++;
	} else {
		$deleteCount++;
		msg("delete: $ldapDN");
	}
}

## tidy up
$ldap->unbind;   # take down session
errMsg("");
if ($ldapDNF ne "") {
	errMsg(singural($lineCount, " line", " lines") . " read from file");
	errMsg(singural($ignoreCount, " line", " lines") . " ignored") if $ignoreCount;
	errMsg(singural($failCount, " unknown line", " unknown lines") . " skipped") if $failCount;
	errMsg(singural($fieldCount, " data line", " data lines") . " processed");
	errMsg(singural($ldapDnCount, " dn line", " dn lines") . " identified") if !$quiet;
}
errMsg(singural($deleteCount, " entry", " entries") . " deleted from directory");
errMsg(singural($ldapErrorCount, " ldap error", " ldap errors") . " reported") if $ldapErrorCount;
errTMsg("...$progName exits normally") if !$quiet;

#### end of main
