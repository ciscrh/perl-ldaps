#!/usr/bin/perl
# ldapAddEntry.pl
#
# carry out an ldap add operation using specified dn and attributes
# dn and attributes supplied as input params or text file containing DNs and attribs
# uses the entry object version of the ldap->add method ####
# v1.02 crh 15-feb-09 -- initial release, based on ldapSearch
# v1.11 crh 18-feb-09 -- renamed (was ldapAdd) and revamped to use ldapAddEntry()

#### WARNING -- this does not work on the linux box, whereas ldapAdd.pl does ####
#### therefore this script is deprecated and is no longer maintained         ####

use warnings;
use strict;
use lib '../crhLib';	# crh custom packages
use Net::LDAP;
use Net::LDAPS;
use Net::LDAP::Entry;	#### probably the source of the problem on linux boxes
use Getopt::Std;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhFile;	# custom file subroutines
use crhString;	# custom string subroutines

#### sanity checks

my $progName = "ldapAddEntry";
my $debug = 0;	# 1 --> debug on, 0--> debug off
my %opts = ();
my $ldapHost = 'basswood.lits.shu.ac.uk';	# optional param
my $ldapPort = 636;	 # optional param
my $ldapSSL = 1;	# optional switch
my $ldapUser="cn=devAdmin,ou=devCRH,o=shu";	# optional param
my $ldapPw = "orun4pix";	# optional param
my $ldapDN = "";	 # mandatory param
my $ldapAttribs = "";	# mandatory param
my $ldapEntryF = ""; # alternative single mandatory param
my %ldapAttribs = ();	
my $throttleSec = 2;	# optional param -- how long to sleep
my $throttleBatch = 50; #  -- how often to sleep
my $fMesg = "";

my $ldap;
my $mesg;
my $entry = 0;	# value set for initial tests
my $fileH;
my $fileLine;
my $entryCount = 0;
my $lineCount = 0;
my $fieldCount = 0;
my $paramOK = 1;	# params check
my $firstDN = 0;

#### subroutines

sub processAttribs ($) {
# process attrib input param
# arg: attrib list string (in format name1:value1,name2:value2...)
# returns hash with name keys and string of values separated by :
# so embedded colons in values not permitted here to keep things simple

	my %attrib;
	my @attribs;
	my $attr;
	my @attrs = split(/[ ,]/, $_[0]);	# space or comma delimited
	my @nameValue;
	
	foreach $attr (@attrs) {	# each name:value pair
		@nameValue = split(/:/, $attr);	# colon delimited
		if (exists($attrib{$nameValue[0]})) {	# extend list string
			$attrib{$nameValue[0]} = $attrib{$nameValue[0]} . ":##:" . $nameValue[1];
		} else {	# add single element list string
			$attrib{$nameValue[0]} = $nameValue[1];
		}
	}
	return %attrib;
}
		
sub processFileAttrib {
# process single attrib line from input file
# args: attrib line (in format name:value), ref to hash of name keys and strings of values
# modifies referenced hash directly, no need to return anything
# complicated by the fact that the values may contain colons

	my $attribRef = $_[1];	# ref to hash
	my $name = $_[0];
	my $value = $_[0];
	
	$name =~ s/:.+//;	# text up to first colon
	$name = trim($name);
	$value =~ s/^[^:]+://;	# text after first colon
	$value = trim($value);
	if (exists($attribRef->{$name})) {	# extend list string
		$attribRef->{$name} = $attribRef->{$name} . ":##:" . $value;
	} else {	# add single element list string
		$attribRef->{$name} = $value;
	}
}

sub fillEntry {
# add attributes to entry
# args: ref to entry, ref to attribs hash

	my $entryRef = $_[0];
	my $attribsRef = $_[1];
	my $name;
	my $valueList;
	my @values;

	foreach $name (keys %$attribsRef) {
		$valueList = $attribsRef->{$name};
		dbgMsg($name . ": $valueList");
		if ($valueList =~ m/:##:/) {	# list
			@values = split(/:##:/, $valueList);
			$$entryRef->add($name => [@values]);
		} else {	# single value
			$$entryRef->add($name => $valueList);
		}
	}
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

errMsg("$progName -- carry out ldap add using supplied dn and attributes");
errMsg("usage: $progName.pl [-n _dn -a _attribs|-E _entryFile] -t _sec");
errMsg("usage:               -h _host -u _username -p _pw -P _port -d -i");
errMsg("defaults to test mode on shu-si if optional parameters omitted\n");

## process input params
dbgMsg("process command line switches...");
getopts('dia:E:h:n:p:P:t:u:', \%opts);

if ($opts{a}) {
	$ldapAttribs = $opts{a};
	errMsg("ldap attributes = $ldapAttribs");
	%ldapAttribs = processAttribs($ldapAttribs);
}
if ($opts{h}) {
	$ldapHost = $opts{h};
	errMsg("ldap host = $ldapHost");
}
if ($opts{u}) {
	$ldapUser = $opts{u};
	errMsg("authentication username dn = $ldapUser");
}
if ($opts{p}) {
	$ldapPw = $opts{p};
	errMsg("authentication password supplied");
}
if ($opts{P}) {
	$ldapPort = $opts{P};
	errMsg("host ldap port = $ldapPort");
}
if ($opts{t}) {
	$throttleSec = $opts{t};
	errMsg("throttle sleep time = $throttleSec");
}
if ($opts{i}) {
	$ldapSSL = 0;
	errMsg("insecure ldap enabled");
	if (!$opts{P}) {	# change default port
		$ldapPort = 389;
		errMsg("[host ldap port = $ldapPort]");
	}
}
if ($opts{d}) {
	$debug = 1;
	setDbg($debug);
	errMsg("debug mode enabled");
}
if ($opts{n}) {
	$ldapDN = $opts{n};
	errMsg("ldap dn = $ldapDN");
} elsif (!$opts{E}) {
	statusErrMsg("fatal", "inputParams"," abort program: no dn provided");
	$paramOK = 0;
}
if ($opts{E}) {
	$ldapEntryF = $opts{E};
	errMsg("ldap dn file = $ldapEntryF");
	($ldapEntryF, $fMesg) = checkInfile($ldapEntryF);
	if (!$ldapEntryF) {
		statusErrMsg("fatal", "inputParams", "abort program: $fMesg");
		$paramOK = 0;
	}
	$ldapEntryF = $opts{E};
}

errMsg("") if $debug;
dbgMsg("host     = $ldapHost");
dbgMsg("port     = $ldapPort");
dbgMsg("user     = $ldapUser");
dbgMsg("pw       = $ldapPw");
dbgMsg("dn       = $ldapDN");
dbgMsg("file     = $ldapEntryF");
dbgMsg("attribs  = $ldapAttribs");
dbgMsg("throttle = $throttleSec");
if ($ldapSSL) {
	dbgMsg("ssl      = enabled (ldaps)\n");
} else {
	dbgMsg("ssl      = disabled (ldap)\n");
}

if ((($ldapAttribs eq "")||($ldapDN eq ""))&&($ldapEntryF eq "")) {
	statusErrMsg("fatal", "inputParams", "abort program: insufficient params supplied");
	die "\n";
} elsif (!$paramOK) {
	die "\n";
}

## make ldap connection
errTMsg("connect to $ldapHost:$ldapPort as $ldapUser ...");
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

## process add operations
if ($ldapEntryF) {	# process data file, if supplied (takes precedence)
	if (open $fileH, $ldapEntryF) {
		errMsg("processing entry data file $ldapEntryF...");
		while ($fileLine = <$fileH>) {
			chomp($fileLine);
			$lineCount++;
			$fileLine = trim($fileLine);	# trim whitespace
			next if (($fileLine =~ m/^#/)||(!length($fileLine)));	# blank & #
			if ($fileLine =~ m/^[^:]+:.+/) {	# data line
				$fieldCount++;
			} else {	# ignore: not a data line
				next;
			}
			if ($fileLine =~ m/^dn\s*:.+/i) {	# start of entry (dn:)
				$firstDN = 1;
				if ($entry) {	# add previous complete entry
					fillEntry(\$entry, \%ldapAttribs);
					$mesg = ldapAddEntry($ldap, $entry);
					if (!$mesg->is_error()) {
						msg("dn: " . $entry->dn());
						$entryCount++;
					}
					if ($throttleSec && !($entryCount % $throttleBatch)) {
						errTMsg("pausing for $throttleSec seconds...");
						sleep($throttleSec);
					}
				}
				$fileLine =~ s/^dn:\s*//i;	# remove dn: prefix
				dbgMsg("dn: $fileLine");
				$entry = Net::LDAP::Entry->new($fileLine);
				%ldapAttribs = ();
			} elsif ($firstDN) {	# process attribute
					processFileAttrib($fileLine, \%ldapAttribs);
			}
		}
		close($fileH);
		if ($entry) {	# add previous complete entry
			fillEntry(\$entry, \%ldapAttribs);
			$mesg = ldapAddEntry($ldap, $entry);
			if (!$mesg->is_error()) {
				msg("dn: " . $entry->dn());
				$entryCount++;
			}
		}
	} else {
		statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening entry file");
		die "\n";
	}
} else {	# process input data params if no input file
	errMsg("dn: $ldapDN");
	$entry = Net::LDAP::Entry->new($ldapDN);
	fillEntry(\$entry, \%ldapAttribs);
	$mesg = ldapAddEntry($ldap, $entry);
	if (!$mesg->is_error()) {
		msg("dn: " . $entry->dn());
		$entryCount++;
	}
}

## tidy up
$mesg = $ldap->unbind;   # take down session
errMsg("");
if ($ldapEntryF ne "") {
	errMsg("$lineCount lines read from file");
	errMsg("$fieldCount data lines processed");
}
errMsg("$entryCount entries added to directory");
errTMsg("...$progName exits successfully");

#### end of main
