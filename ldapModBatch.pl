#!/usr/bin/perl
# ldapModBatch.pl
#
# carry out a batch ldap modify operations
# requires entry file to act on as mandatory param
# v1.00 crh 05-sep-10 -- initial release, based on ldapModify
# v1.10 crh 08-sep-10 -- move/rename functionality added
# v1.22 crh 26-sep-10 -- some subroutines moved into crhEntry
# v1.32 crh 01-oct-11 -- home version (underscore 2 space added)
# v1.40 crh 10-jul-12 -- reviewed (refactoring & file input param processing)
use warnings;
use strict;
use lib '../crhLib';	# crh custom packages
use Net::LDAP;
use Net::LDAPS;
use crhDebug;	# custom debug subroutines
use crhLDAP;	# custom ldap subroutines
use crhFile;	# custom file subroutines
use crhString;	# custom string subroutines
use crhArray;	# custom array subroutines
use crhArg;	# custom argument subroutines
use crhEntry;	# custom entry file subroutines

#### sanity checks

my $progName = "ldapModBatch";
my $lcMode = 1;	# convert attribute names to lowercase
my $debug = 0;	# optional param default value -- 1 = debug on, 0 = debug off
my $test = 0;	# optional param default value -- 1 = test on, 0 = test off
my $ldapHost = '127.0.0.1';	# optional param default value, works for me :-)
my $ldapPort = 636;	 # optional param
my $ldapSSL = 1;	# optional switch
my $ldapUser="";	# mandatory param
my $ldapPw = "";	# optional param
my $ldapEntryF = ""; # mandatory param
my $ldapDefaultMode = "";	# optional default mode {A}dd, {D}elete, {R}eplace
my $lastChangeMode = "";	#	used if no changemode specified for current dn
my $quiet = 0;	# optional param default value -- turn off some informational output
my $throttleSec = 5;	# optional param default value -- how long to sleep
my $ldapDefaultDest = "";	# optional move location param
my $throttleBatch = 100; # how often to sleep
my $ldapDN = "";
my @ldapDNs = ();	# used to retrieve DNs in entry file order for processing
my $ldapMode = "";
my $fileLine = "";
my @ldapAction = ();	# build up array of actions for current DN
my %ldapActions = ();	# hash{DN} of ldap actions
my %ldapMoves = ();	# hash{DN} of ldap move/rename actions
my %ldapAddActions = ();
my %ldapDelActions = ();
my %ldapReplActions = ();
my $ldapDest = "";
my $ldapRename = "";
my $tmpARef;

my $ldap;
my $fileH;

my $paramOK = 1;	# params check
my $modAction = 0;	# modify action check
my $modifyCount = 0;
my $lineCount = 0;
my $ignoreCount = 0;
my $entryCount = 0;
my $actionCount = 0;
my $failCount = 0;
my $modeCount = 0;
my $changeCount = 0;
my $ldapDnCount = 0;
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

sub setDNActions ($) {
# clear and set attrib and values in global hashes
# no need to process ldapMoves, it can only have one value per DN
# args: \@dnActions

	my $arrRef = $_[0];
	my $action;
	my $mode;
	my $attrib;
	my $val;

	%ldapAddActions = ();
	%ldapDelActions = ();
	%ldapReplActions = ();

	foreach $action (@$arrRef) {
		$mode = @$action[0];
		if ($lcMode) {	# avoids bad case misunderstandings
			$attrib = lc(@$action[1]);
		} else {
			$attrib = @$action[1];
		}
		if (@$action == 3) {
			$val = @$action[2];
		} else {	# no value provided
			$val = "deleteAllValues";
		}
		if ($mode eq "add") {
			if (exists($ldapAddActions{$attrib})) {	# update hash entry
				$tmpARef = $ldapAddActions{$attrib};
				push @$tmpARef, $val;
			} else {	# create hash entry
				my @tmpArray = ($val);
				$ldapAddActions{$attrib} = \@tmpArray;
			}
		} elsif ($mode eq "delete") {
			if ($val ne "deleteAllValues") {
				if (exists($ldapDelActions{$attrib})) {	# update hash entry
					$tmpARef = $ldapDelActions{$attrib};
					push @$tmpARef, $val;
				} else {	# create hash entry
					my @tmpArray = ($val);
					$ldapDelActions{$attrib} = \@tmpArray;
				}
			} else {	# delete all attrib values
				my @tmpArray = ($val);
				$ldapDelActions{$attrib} = \@tmpArray;
			}
		} else {	# replace mode
			if ($val ne "deleteAllValues") {
				if (exists($ldapReplActions{$attrib})) {	# update hash entry
					$tmpARef = $ldapReplActions{$attrib};
					push @$tmpARef, $val;
				} else {	# create hash entry
					my @tmpArray = ($val);
					$ldapReplActions{$attrib} = \@tmpArray;
				}
			} else {	# delete all attrib values
				my @tmpArray = ($val);
				$ldapReplActions{$attrib} = \@tmpArray;
			}
		}
	}
}

sub modifyDN ($) {
# process ldapModify action for current ldapDN
# all three modes can be processed as required
# arg: $ldapDN

	my $dn =$_[0];

	foreach my $key (keys %ldapDelActions) {
		modifyAttrib($dn, "delete", $key, $ldapDelActions{$key});
		if (ldapIsError()) {
			statusErrMsg("warn", "modifyDN", "delete attribute failed: $dn");
			$ldapErrorCount++;
		}
	}
	foreach my $key (keys %ldapReplActions) {
		modifyAttrib($dn, "replace", $key, $ldapReplActions{$key});
		if (ldapIsError()) {
			statusErrMsg("warn", "modifyDN", "replace attribute failed: $dn");
			$ldapErrorCount++;
		}
	}
	foreach my $key (keys %ldapAddActions) {
		modifyAttrib($dn, "add", $key, $ldapAddActions{$key});
		if (ldapIsError()) {
			statusErrMsg("warn", "modifyDN", "add attribute failed: $dn");
			$ldapErrorCount++;
		}
	}
}

sub modifyAttrib ($$$$) {
# process ldapModify action for an attribute for current ldapDN
# args: $ldapDN, $mode, $attrib, \@attribVals

	my $dn =$_[0];
	my $mode = $_[1];
	my $attrib = $_[2];
	my $attribsARef = $_[3];
	my @attribs = @$attribsARef;

	dbgMsg("modifyAttribDN>>$dn");
	dbgMsg("modifyAttrib>>$mode: $attrib=>" .  arr2bsv(@$attribsARef));
	if (($mode ne "add") && (@$attribsARef[0] eq "deleteAllValues")) {
		ldapModify($ldap, $dn, $mode, $attrib);
	} else {
		if (@attribs == 1) {
			ldapModify($ldap, $dn, $mode, $attrib, $attribs[0]);
		} else {
			ldapModify($ldap, $dn, $mode, $attrib, \@attribs);
		}
	}
}

sub help {
	errMsg("$progName -- carry out ldap modify on supplied entry file objects");
	errMsg("usage: $progName.pl -E _entryFile -u _username [-p _pw][-h _host][-P _port]");
	errMsg("         [-M _defaultMove|-R{eplace}|-D{elete}|-A{dd}]");
	errMsg("         [-T{est}][-t _sec][-q{uiet}][-d{ebug}][-i{nsecure}]");
	errMsg("hints: uses advanced syntax entry file to carry out modifications to entries");
	errMsg("       default modify mode and move location can be set using parameters");
	errMsg("       otherwise they must be set in the entry file\n");
}

sub debugParam {
# output post parameter processing information if debug mode enabled

	errMsg("") if $debug;
	dbgMsg("host         = $ldapHost");
	dbgMsg("port         = $ldapPort");
	dbgMsg("user         = $ldapUser");
	if (argGetPw('p')) {
		dbgMsg("pw           = $ldapPw");
	} elsif ($ldapPw) {
		dbgMsg("pw           = supplied interactively");
	}
	dbgMsg("entry file   = $ldapEntryF");
	dbgMsg("throttle     = $throttleSec");
	dbgMsg("default mode = " . trueFalse($ldapDefaultMode, $ldapDefaultMode, "not set"));
	dbgMsg("default move = $ldapDefaultDest");
	dbgMsg("quiet mode   = " . trueFalse($quiet, "enabled", "disabled"));
	dbgMsg("test mode    = " . trueFalse($test, "enabled", "disabled"));
	dbgMsg("ssl          = " . trueFalse($ldapSSL, "enabled (ldaps)\n", "disabled (ldap)\n"));
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

## process input params

argSetOpts ('AdDiqRTE:h:M:p:P:t:u:');

$quiet = argSetQuiet(argGetFlag('q'));
ldapSetQuiet($quiet);	# suppress LDAP error messages in quiet mode
entrySetQuiet($quiet);	# suppress entry error messages in quiet mode
$debug = setDbg(argGetFlag('d', 'debug mode enabled'));
help() if !$quiet;
dbgMsg("process command line switches...");

$test = argGetFlag('T', 'test-only mode enabled');
if (argGetFlag('A', 'default change mode: add')) {
	$ldapDefaultMode = "add";
}
if (argGetFlag('D', 'default change mode: delete')) {
	if ($ldapDefaultMode ne "") {
		statusErrMsg("warn", "inputParams", "default change mode redefined");
	}
	$ldapDefaultMode = "delete";
}
if (argGetFlag('R', 'default change mode: replace')) {
	if ($ldapDefaultMode ne "") {
		statusErrMsg("warn", "inputParams", "default change mode redefined");
	}
	$ldapDefaultMode = "replace";
}
if (argGetParam('M')) {
	$ldapDefaultDest = argGetParam('M', 'default move location: ');
}
if (argGetParam('h')) {
	$ldapHost = argGetParam('h', 'ldap host: ');
}
if (argGetParam('P')) {
	$ldapPort = argGetParam('P', 'ldap port: ');
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
$ldapEntryF = argGetInputFile ('E', "entry file: ", "no entry file provided");
if (!$ldapEntryF) {
	statusErrMsg("fatal", "inputParams", "abort program: entry file problem");
	$paramOK = 0;
} else {
	$ldapEntryF = absPath(dos2UnixPath($ldapEntryF));
}
$ldapUser = argGetParam('u');
if (!$ldapUser && !$test) {	# no ldap bind user provided
	statusErrMsg("fatal", "inputParams", "abort program: no authentication user provided");
	$paramOK = 0;
	errMsg("authentication user dn: $ldapUser") if !$quiet;
} else {
	under2Space($ldapUser);
	errMsg("authentication user dn: $ldapUser") if !$quiet;
}
if (!$test && $paramOK) {
	$ldapPw = argGetPw('p', "password supplied", "no password supplied...", "enter password: ");
} elsif (argGetPw('p')) {
		$ldapPw = argGetPw('p', "password supplied");
}

debugParam();
if (!$paramOK) {
	die "\n";
}

## make ldap connection

if (!$test) {
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
}

## process entry file

if (open $fileH, $ldapEntryF) {	# process file
	dbgMsg("file: $ldapEntryF");
	errMsg("processing entry file...");
	while ($fileLine = <$fileH>) {
		$lineCount++;
		chomp($fileLine);
		$fileLine = trim($fileLine);	# trim whitespace
		if (entryIsBlank($fileLine)) {	# ignore blank & comment (#) lines
			$ignoreCount++;
			next;
		} elsif (!entryIsValidLine($fileLine)) {	# basic syntax check
			$failCount++;
			next;
		}
		if (entryIsDN($fileLine)) {	# initialise variables
			$ldapDnCount++;
			dbgMsg("entryIsDN(true)>>$fileLine");
			$ldapDN = entryGetDN($fileLine);
			if ($ldapDefaultMode) {
				$ldapMode = $ldapDefaultMode;
			} else {
				$ldapMode = $lastChangeMode;
		}
			dbgMsg("initial changemode>>$ldapMode");
			$ldapDest = "";
			$ldapRename = getRDN($ldapDN);
			$entryCount++;
			errMsg("processing DN $ldapDN") if !$quiet;
		} elsif (!($entryCount || entryIsDN($fileLine))) {	# no current DN value
			$failCount++;
			dbgMsg("line skipped>>$fileLine");
			next;
		} else {	# process action
			if (entryIsMoveRename($fileLine)) {	# move/rename command can appear anytime after dn
				dbgMsg("entryIsMoveRename(true)>>$fileLine");
				$actionCount++;
				$changeCount++;
				if (entryIsMove($fileLine)) {
					$ldapDest = entryGetMove($fileLine, $ldapDefaultDest);
				} else {
					$ldapRename = entryGetRename($fileLine);
				}
				my @tmpMoves = ($ldapRename, $ldapDest);
				if (!(exists($ldapActions{$ldapDN}) || exists($ldapMoves{$ldapDN}))) {	# update @ldapDNs
					push @ldapDNs, $ldapDN;
					dbgMsg("ldapDNsFrom>>$ldapDN");
				}
				$ldapMoves{$ldapDN} = \@tmpMoves;	# create/overwrite moves hash entry
				next;
			}
			if (entryIsMode($fileLine)) {
				dbgMsg("entryIsMode(true)>>$fileLine");
				$ldapMode = entryGetMode($fileLine);
				if ($ldapMode) {
					$actionCount++;
					$modeCount++;
					$lastChangeMode = $ldapMode;
				} else {
					$failCount++;
				}
				next;
			} elsif (entrySetAction($fileLine, $ldapMode, \@ldapAction, $lcMode)) {
				$changeCount++;
				$actionCount++;
				if (exists($ldapActions{$ldapDN})) {	# update hash entry
					$tmpARef = $ldapActions{$ldapDN};
					push @$tmpARef, [ @ldapAction ];
				} else {	# create initial hash entry
				if (!exists($ldapMoves{$ldapDN})) {	# update @ldapDNs
					push @ldapDNs, $ldapDN;
					dbgMsg("ldapDNsMode>>$ldapDN");
				}
					push my @tmpArray, [ @ldapAction ];
					$ldapActions{$ldapDN} = \@tmpArray;
				}
			} else {	# set action failed
				$failCount++;
				dbgMsg("entrySetAction(false)>>$fileLine")
			}
		}
	}
	close($fileH);
} else {
	statusErrMsg("fatal", "fileOpen", "abort program: unexpected error opening entry file");
	die "\n";
}

## process entries

if ($test) {	# just display sorted entry actions
	errMsg("\nlist entries (test mode only)...");
} else {	# modify entries
	errMsg("\nupdate entries...");
}
foreach $ldapDN (@ldapDNs) {
	dbgMsg("dn>>$ldapDN");
	if (exists $ldapActions{$ldapDN}) {
		my $ldapActionARef = $ldapActions{$ldapDN};
		if ($test) {	# just display sorted entry actions
			my @ldapAction = arrARefSortLex($ldapActionARef,0,1);
			msg("\n$ldapDN");
			my $arraySize = @ldapAction;
			dbgMsg("action array size:$arraySize");
			foreach my $row (@ldapAction) {	# row is reference to array
				arrPrintBSV(@$row);	# deference row array here
			}
		} else {	# process entry actions
			my @ldapAction = @$ldapActionARef;
			setDNActions(\@ldapAction);
			msg("modify: $ldapDN") if !$quiet;
			modifyDN($ldapDN);
		}
	}
	if (exists $ldapMoves{$ldapDN}) {
		my $ldapMovesARef = $ldapMoves{$ldapDN};
		if ($test) {
			print STDERR "move|";
			my $ldapMovesARef = $ldapMoves{$ldapDN};
			arrPrintBSV(@$ldapMovesARef);
		} else {
			$ldapRename = @$ldapMovesARef[0];
			$ldapDest = @$ldapMovesARef[1];
			msg("move/rename: $ldapDN|$ldapRename|$ldapDest") if !$quiet;
			ldapModDN($ldap, $ldapDN, $ldapRename, $ldapDest, "1");
			if (ldapIsError()) {
				statusErrMsg("warn", "processFile", "move/rename failed: $ldapDN");
				$ldapErrorCount++;
			}
		}
	}
	if (!$test && $throttleSec && !(++$modifyCount % $throttleBatch)) {
		errTMsg("pausing for $throttleSec seconds ($modifyCount)...");
		sleep($throttleSec);
	}
}

## tidy up and summary

$ldap->unbind if !$test;   # take down session

errMsg("");
errMsg(singural($lineCount, " line", " lines") . " read from file");
errMsg(singural($ignoreCount, " line", " lines") . " ignored") if $ignoreCount;
errMsg(singural($failCount, " invalid line", " invalid lines") . " skipped") if $failCount;
errMsg(singural($modeCount, " changemode", " changemodes") . " set") if $modeCount;
errMsg(singural($entryCount, " entry", " entries") . " processed");
errMsg(singural($ldapDnCount, " dn line", " dn lines") . " identified") if !$quiet;
errMsg(singural($changeCount, " change", " changes") . " processed");
errMsg(singural($ldapErrorCount, " ldap error", " ldap errors") . " reported") if $ldapErrorCount;
errTMsg("...$progName exits normally") if !$quiet;

#### end of main
