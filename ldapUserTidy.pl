#!/usr/bin/perl
# ldapUserTidy.pl
#
# tidy up users membership of users using (secure) ldap
# v1.02 crh 05-feb-09 -- initial release, based on ldapUserTidy
# v1.12 crh 19-feb-09 -- renamed ldapUserTidy
# v1.21 crh 12-mar-10 -- defaults revamped, password processing improved and test/verbose modes added

use warnings;
use strict;
use lib '../crhLib';	# crh custom packages
use POSIX;
use Net::LDAP;
use IO::Socket::SSL;
use Net::LDAPS;
use Getopt::Std;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhString;	# custom string subroutines

#### sanity checks

my $progName = "ldapUserTidy";
my $debug = 0;	# 1 --> debug on, 0--> debug off
my %opts = ();
my $ldapHost = 'zenldap.shu.ac.uk';	# optional param default value
my $ldapPort = 636;	 # optional param default value
my $ldapFilter = "";	# mandatory param
my $ldapBase = "o=shu";	# optional param default value
my $ldapSSL = 1;	# optional switch default value (1 -> secure mode)
my $algorithm = "union";	# optional param default value
my $verbose = 0;	# optional param default value (0 -> not verbose mode)
my $test = 0;	# optional param default mode (0 -> not test mode
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $delay = 10;	# allow for IDM synchronisation delays
my $paramOK = 1;	# params check

my $ldap;
my $ldap1;
my $mesg;
my $mesg1;
my $attribs;
my $entry;
my $userDN;
my @keys1;
my @keys2;
my $seList;
my $se;
my $gmList;
my $gm;
my $key;
my $count;

#### main

setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

errMsg("$progName -- tidy up group membership attributes of user objects using ldap");
errMsg("note that it may modify but does not guarantee to tidy up group objects completely");
errMsg("the default union mode is more generous than the alternative intersect mode\n");
errMsg("usage: $progName.pl -f _userCN -h _host -b _searchBase -u _username [-p _pw][-P _port]");
errMsg("usage:          [-v{erbose}|-t{est}][-U{nion}|-I{ntersect}][-i{nsecure}][-d{ebug}]\n");

## process input params

dbgMsg("process command line switches...");
getopts('diItUvb:f:h:p:P:u:', \%opts);

if ($opts{d}) {
	$debug = 1;
	setDbg($debug);
	errMsg("debug mode enabled");
}
if ($opts{f}) {	# mandatory
	$ldapFilter = $opts{f};
	errMsg("filter = $ldapFilter");
} else {
	statusErrMsg("fatal","inputParams","mandatory search filter missing");
	$paramOK = 0;
}
if ($opts{h}) {
	$ldapHost = $opts{h};
	errMsg("ldap host = $ldapHost");
}
if ($opts{b}) {
	$ldapBase = $opts{b};
	errMsg("search base = $ldapBase");
}
if ($opts{P}) {
	$ldapPort = $opts{P};
	errMsg("host ldap port = $ldapPort");
}
if ($opts{i}) {
	$ldapSSL = 0;
	errMsg("insecure ldap selected");
	if (!$opts{p}) {	# change default port
		$ldapPort = 389;
		errMsg("[host ldap port = $ldapPort]");
	}
}
if ($opts{I}) {
	$algorithm = "intersect";
	errMsg("algorithm = $algorithm");
}
if ($opts{U}) {	# wins if both modes specified
	$algorithm = "union";
	errMsg("algorithm = $algorithm");
}
if ($opts{v}) {
	$verbose = 1;
	errMsg("verbose mode enabled");
}
if ($opts{t}) {
	$test = 1;
	errMsg("test mode enabled");
	if (!$verbose) {	# test implies verbose as well
		$verbose = 1;
		errMsg("verbose mode auto-enabled");
	}
}
if ($opts{u}) {
	$ldapUser = $opts{u};
	errMsg("authentication username dn = $ldapUser");
} else {
	statusErrMsg("fatal","inputParams","mandatory authentication user missing");
	$paramOK = 0;
}
if ($opts{p}) {
	$ldapPw = $opts{p};
	errMsg("authentication password supplied");
} elsif ($paramOK) {	# allow -p switch to be omitted -- prompts for password without echoing it
	errMsg("no password supplied...");
	$ldapPw = errPrompt('enter password: ');
}

errMsg("") if $debug;
dbgMsg("host          = $ldapHost");
dbgMsg("port          = $ldapPort");
dbgMsg("user          = $ldapUser");
dbgMsg("pw            = $ldapPw");
dbgMsg("search base   = $ldapBase");
dbgMsg("search filter = $ldapFilter");
dbgMsg("algorithm     = $algorithm");
dbgMsg("ssl           = " . trueFalse($ldapSSL, "enabled (ldaps)", "disabled (ldap)"));
dbgMsg("verbode mode  = " . trueFalse($verbose, "enabled", "disabled (default)"));
dbgMsg("test mode     = " . trueFalse($test, "enabled\n", "disabled (default)\n"));

if (!$paramOK) {
	die "\n";
}

## make ldap connection

errTMsg("connect to $ldapHost:$ldapPort as $ldapUser ...");
if ($ldapSSL) {	# secure connection
	$ldap = ldapsNew($ldapHost, $ldapPort);
	$ldap1 = ldapsNew($ldapHost, $ldapPort);
} else {	# insecure connection
	$ldap = ldapNew($ldapHost, $ldapPort);
	$ldap1 = ldapNew($ldapHost, $ldapPort);
}

$mesg = ldapBind($ldap, $ldapUser, $ldapPw);	# ldap bind
dbgMsg("return code: " . $mesg->code);
dbgMsg("message: " . $mesg->error_name . "..." . $mesg->error_text);

$mesg1 = ldapBind($ldap1, $ldapUser, $ldapPw);	# second ldap bind
dbgMsg("return code: " . $mesg1->code);
dbgMsg("message: " . $mesg1->error_name . "..." . $mesg->error_text);

if (($mesg->code)||($mesg1->code)) {
	statusMsg("fatal","ldapBind","abort program: ldap bind failed");
	die "\n";
}

## ldap search

errTMsg("ldap search for $ldapFilter ...");
$attribs = ['securityEquals', 'groupMembership'];
$mesg = ldapSearch($ldap, $ldapBase, 'sub', "(&($ldapFilter)(objectClass=user))", $attribs);

errMsg("nr of hits: " . $mesg->count);

## process users

foreach $entry ($mesg->entries) { 
	my %member;	# reinitialise hashes for every iteration
	my %security;
	my %union;
	my %inter;
	
	$userDN = $entry->dn();
	msg("");
	tMsg("processing " . $userDN . " (user)");
	$count = 0;
	msg("  securityEquals") if ($verbose);
	$seList = $entry->get_value("securityEquals", asref => 1);
	if ($seList) {
		foreach $se (@$seList) {
			msg("    " . $se) if ($verbose);
			$security{$se} = 1;
			$count++;
		}
	}
	statusErrMsg("info", "processUsers", "$count securityEquals");
	$count = 0;
	msg("  groupMembership") if ($verbose);
	$gmList = $entry->get_value("groupMembership", asref => 1);
	if ($gmList) {
		foreach $gm (@$gmList) {
			msg("    " . $gm) if ($verbose);
			$member{$gm} = 1;
			$count++;
		}
	}
	statusErrMsg("info", "processUsers", "$count groupMembership");
	%union = hashUnion(\%security, \%member);
	%inter = hashIntersect(\%security, \%member);
	if ($verbose) {
		if (($algorithm eq "union") || $test) {
			msg("  union hash (" . (keys %union) . ")");
			hashPrintKey(\%union);
		}
		if (($algorithm eq "intersect") || $test) {
			msg("  intersect hash (" . (keys %inter) . ")");
			hashPrintKey(\%inter);
		}
	}
	
	if ($test) {
		statusErrMsg("info", "processUsers", "test mode, no changes made");
	} else {
		@keys1 = (keys %union);	# defines what attributes are removed
		if ($algorithm eq "intersect") {	# defines what attributes are reinstated
			@keys2 = (keys %inter)	# those appearing in both attribute sets
		} else {
			@keys2 = (keys %union);	# those appearing in either attribute set (default)
		}
	
		errMsg("delete all selected attribute values from user...");
		$mesg1 = ldapModify($ldap1, $entry, 'replace', 'securityEquals');
		$mesg1 = ldapModify($ldap1, $entry, 'replace', 'groupMemberShip');
		
		setQuietLDAP(1) if (!$debug);	# suppress the expected ldap error messages
		errMsg("delete selected user attribute values from selected groups...");
		foreach $key (@keys1) {
			$mesg1 = ldapModify($ldap1, $key, 'delete', 'equivalentToMe', $userDN);
			$mesg1 = ldapModify($ldap1, $key, 'delete', 'member', $userDN);
		}
		setQuietLDAP(0) if (!$debug);	# restore ldap error message reporting
	
		errTMsg("introduce $delay second pause for the benefit of the IDM drivers...");
		sleep $delay;
	
		errTMsg("add required values back in to user and groups...");
	
		errMsg("process user for groups");
		foreach $key (@keys2) {
			$mesg1 = ldapModify($ldap1, $entry, 'add', 'securityEquals', $key);
			$mesg1 = ldapModify($ldap1, $entry, 'add', 'groupMembership', $key);
		}

		errMsg("process groups for user");
		foreach $key (@keys2) {
			$mesg1 = ldapModify($ldap1, $key, 'add', 'equivalentToMe', $userDN);
			$mesg1 = ldapModify($ldap1, $key, 'add', 'member', $userDN);
		}
	}
}

$mesg = $ldap->unbind;   # take down session
$mesg1 = $ldap1->unbind;   # take down session

errMsg("");
errTMsg("...$progName exits successfully");

#### end of main
