#!/usr/bin/perl
# ldapModDN.pl
#
# carry out a simple ldap moddn operation on given DNs
# ldap dn supplied as input param or text file containing one dn per line
# only one new rdn and/or superior can be given
# no rdn can be specified if entry file used
# new rdn taken as existing rdn if not given
# v1.00 crh 01-mar-09 -- initial release, based on ldapModify
# v1.10 crh 31-aug-10 -- defaults revamped, password processing improved, quiet switch added

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

#### sanity checks

my $progName = "ldapModDN";
my $debug = 0;	# 1 --> debug on, 0--> debug off
my %opts = ();
my $ldapHost = 'zenldap.shu.ac.uk';	# optional param default value
my $ldapPort = 636;	 # optional param
my $ldapSSL = 1;	# optional switch
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $ldapDN = "";	 # mandatory param
my $ldapDNF = ""; # alternative mandatory param
my $ldapNewRDN = "";	# optional param
my $ldapNewSup = "";	# optional param
my $ldapDelOldRDN = 1;	# optional param
my $throttleBatch = 100; #  how often to sleep
my $throttleSec = 2;	# optional param -- how long to sleep
my $fMesg = "";
my $quiet = 0;	# optional param default value -- turn off some informational output

my $ldap;
my $mesg;
my $fileH;

my $paramOK = 1;	# params check
my $moddnCount = 0;
my $lineCount = 0;
my $fieldCount = 0;

#### subroutines

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

## process input params

dbgMsg("process command line switches...");
getopts('dikqe:E:h:p:P:r:s:t:u:', \%opts);

if ($opts{q}) {
	$quiet = 1;
#	errMsg("quiet mode enabled");
}

errMsg("$progName -- carry out ldap moddn on supplied objects") if !$quiet;
errMsg("usage: $progName.pl [-e _entryDN|-E _entryListFile][-t _sec]") if !$quiet;
errMsg("usage:      -h _host -u _username -p _pw -P _port [-q][-d][-i]") if !$quiet;
errMsg("usage:      -r _newRDN -s _newSuperior [-k]");

if ($opts{d}) {
	$debug = 1;
	setDbg($debug);
	errMsg("debug mode enabled");
}
if ($opts{r}) {
	$ldapNewRDN =$opts{r};
	errMsg("ldap new RDN = $ldapNewRDN") if !$quiet;
} elsif ($opts{e} && $opts{s}) {	# extract rdn from dn
	$ldapNewRDN = getRDN($opts{e});
	errMsg("ldap new RDN = $ldapNewRDN (inferred)") if !$quiet;
} else {
	$paramOK = 0;
}
if ($opts{s}) {
	$ldapNewSup =$opts{s};
	errMsg("ldap new superior = $ldapNewSup") if !$quiet;
	$paramOK = 1;
}
if (!$paramOK) {
	statusErrMsg("fatal", "inputParams", "abort program: neither rdn nor superior given");
}
if ($opts{e}) {
	$ldapDN = $opts{e};
	errMsg("ldap dn = $ldapDN") if !$quiet;
} elsif (!$opts{E}) {
	statusErrMsg("fatal", "inputParams","abort program: no dn given");
	$paramOK = 0;
}
if ($opts{k}) {
	$ldapDelOldRDN = 0;
	errMsg("ldap keep old RDN set") if !$quiet;
}
if ($opts{h}) {
	$ldapHost = $opts{h};
	errMsg("ldap host = $ldapHost") if !$quiet;
}
if ($opts{P}) {
	$ldapPort = $opts{P};
	errMsg("host ldap port = $ldapPort") if !$quiet;
}
if ($opts{t}) {
	$throttleSec = $opts{t};
	errMsg("throttle sleep time = $throttleSec") if !$quiet;
}
if ($opts{i}) {
	$ldapSSL = 0;
	errMsg("insecure ldap enabled") if !$quiet;
	if (!$opts{P}) {	# change default port
		$ldapPort = 389;
		errMsg("[host ldap port = $ldapPort]") if !$quiet;
	}
}
if ($opts{E}) {
	$ldapDNF = $opts{E};
	errMsg("ldap dn file = $ldapDNF") if !$quiet;
	($ldapDNF, $fMesg) = checkInfile($ldapDNF);
	if (!$ldapDNF) {
		statusErrMsg("fatal", "inputParams", "abort program: $fMesg");
		$paramOK = 0;
	}
	if ($opts{r}) {
		statusErrMsg("fatal", "inputParams", "abort program: same rdn given for multiple entries");
		$paramOK = 0;
	}
	if (!$opts{s}) {
		statusErrMsg("fatal", "inputParams", "abort program: no superior given for multiple entries");
		$paramOK = 0;
	}
	$ldapDNF = $opts{E};
}
if ($opts{u}) {
	$ldapUser = $opts{u};
	errMsg("authentication username dn = $ldapUser") if !$quiet;
} else {
	statusErrMsg("fatal", "inputParams"," abort program: no authentication username provided");
	$paramOK = 0;
}
if ($opts{p}) {
	$ldapPw = $opts{p};
	errMsg("authentication password supplied") if !$quiet;
} elsif ($paramOK) {	# allow -p switch to be omitted -- prompts for password without echoing it
	errMsg("no password supplied...") if !$quiet;
	$ldapPw = errPrompt('enter password: ');
}

errMsg("") if $debug;
dbgMsg("host           = $ldapHost");
dbgMsg("port           = $ldapPort");
dbgMsg("user           = $ldapUser");
dbgMsg("pw             = $ldapPw");
dbgMsg("entry dn       = $ldapDN");
dbgMsg("entry file     = $ldapDNF");
dbgMsg("new rdn        = $ldapNewRDN");
dbgMsg("new superior   = $ldapNewSup");
dbgMsg("throttle       = $throttleSec");
dbgMsg("delete old rdn = " . trueFalse($ldapDelOldRDN, "enabled", "disabled"));
dbgMsg("quiet mode     = " . trueFalse($quiet, "enabled", "disabled"));
dbgMsg("ssl            = " . trueFalse($ldapSSL, "enabled (ldaps)\n", "disabled (ldap)\n"));

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
dbgMsg("return code: " . $mesg->code);
dbgMsg("message: " . $mesg->error_name . "..." . $mesg->error_text);

if ($mesg->code) {
	statusMsg("fatal","ldapBind","abort program: ldap bind failed");
	die "\n";
}

## process modify operations

if ($ldapDNF) {	# process entry file
	if (open $fileH, $ldapDNF) {	# process file (takes precedence)
		dbgMsg("file: $ldapDNF");
		errMsg("processing dn file...");
		while ($ldapDN = <$fileH>) {
			$lineCount++;
			chomp($ldapDN);
			$ldapDN = trim($ldapDN);	# trim whitespace
			next if (($ldapDN =~ m/^#/)||(!length($ldapDN)));	# ignore blank & # lines
			$fieldCount++;
			next if ($ldapDN !~ m/^dn:.+/i);	# ignore lines not starting dn:
			$ldapDN =~ s/^dn:\s*//i; # remove prepended dn:
			dbgMsg($ldapDN);
			$moddnCount++;
			if ($ldapDelOldRDN) {
				ldapModDN($ldap, $ldapDN, getRDN($ldapDN), $ldapNewSup, "1");
			} else {
				ldapModDN($ldap, $ldapDN, getRDN($ldapDN), $ldapNewSup);
			}
			if ($throttleSec && !($moddnCount % $throttleBatch)) {
				errTMsg("pausing for $throttleSec seconds ($moddnCount)...");
				sleep($throttleSec);
			}
		}
		close($fileH);
		statusErrMsg("info", "entryFile", "$lineCount lines read from file");
		statusErrMsg("info", "entryFile", "$moddnCount records processed");
	} else {
		statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening dn file");
		die "\n";
	}
} else {	# process input param entry DN
	if ($ldapDelOldRDN) {
		ldapModDN($ldap, $ldapDN, $ldapNewRDN, $ldapNewSup, "1");
	} else {
		ldapModDN($ldap, $ldapDN, $ldapNewRDN, $ldapNewSup);
	}
}

## tidy up

$mesg = $ldap->unbind;   # take down session

errMsg("");
if ($ldapDNF ne "") {
	errMsg("$lineCount lines read from file");
	errMsg("$fieldCount data lines processed");
}
errMsg("$moddnCount entries processed") if ($ldapDNF);
errTMsg("...$progName exits successfully") if !$quiet;

#### end of main
