#!/usr/bin/perl
#
# dn2rdn.pl
# converts DNs to RDNs in DN entry record files supplied as input
# writes output to renamed files using different extension
# renames processed files, giving them an .bkp extension
# v1.00 crh 10-mar-09 -- loosely based on siRemDupLines8
# v1.10 crh 13-mar-09 -- rename/backup switches simplifed

use strict;
use warnings;
use File::Basename;
use POSIX;
use Getopt::Std;
use lib '../crhLib';	# crh custom packages
use crhDebug;	# custom debug subroutines
use crhFile;	# custom file subroutines
use crhString;	# custom string subroutines

#### sanity checks
my $progName = "dn2rdn";
my $debug = 0;	# 1 --> debug on, 0 --> debug off
my %opts = ();
my $inFileExt = "";
my $outFile = "";
my $outFileExt = ".cn";	# optional param
my $renameFileExt = ".bkp"; # optional param
my $searchDir = ".\\";	# optional param -- defaults to current dir
my @inFiles = ();
my $inFiles = "";
my $inFile = "";
my $total = 0;
my $totalDN = 0;
my %unique = ();
my $totalInFile = 0;
my $totalRenFile = 0;
my $paramOK = 1;
my $cn = "";
my $msg = "";
my $rename = 0;

#### define functions

sub fileExt ($) {
# return filename extension
# args: filename

	my $file = "";
	my $fileF = "";
	my $fileD = "";
	my $fileE = "";
	
	($fileF, $fileD, $fileE) = fileparse($_[0], qr/\..*/);
	return $fileE;
}

sub renInfile (*$) {
# rename input file

	my $inFile = "";
	my $inFileF = "";
	my $inFileD = "";
	my $inFileE = "";
	my $ok = "0";
	my $argFile = $_[0];
	my $newExt = $_[1];	# processed input file extension

	($inFileF, $inFileD, $inFileE) = fileparse($argFile, qr/\..*/);
	$inFile = $inFileD . $inFileF . $newExt;

	if (-e $inFile) {
	statusErrMsg("warning", "renInfile", "rename skipped: $inFile already exists");
	} elsif (rename($argFile, $inFile)) {
		$ok = $inFile;
	} else {
		statusErrMsg("error", "renInfile", "rename skipped: cannot rename $argFile to $inFile");
	}
	if ($ok) {
		statusErrMsg("info", "renInfile", "$inFileF.$inFileE renamed to $inFileF.$newExt");
	}
	return $ok;
}

sub revampLine ($) {
# return cn record, or empty string if not dn
# args: dn record

	my $revamp = $_[0];

	chomp($revamp);
	if ($revamp =~ m/^\s*dn:/i) {	# dn record
		$revamp =~ s/(^\s*dn:\s*)([^,]+)(,.+)/$2/i;
		return $revamp . "\n";
	} else {
		return "";
	}
}

#### main

errTMsg("$progName invoked");
setDbg($debug);
setDbgProgName($progName);
statusDbgMsg("DEBUG", "main", "debug enabled");

errMsg("$progName -- generate cn record files from supplied dn record files");
errMsg("usage: $progName.pl -i _inFileExt [-s _searchDir] [-r [_renameFileExt]] -o [_outfileExt] -d");

## process input params
dbgMsg("process command line switches...");
getopts('d:i:o:r:s:', \%opts);

if ($opts{d}) {
	$debug = 1;
	setDbg($debug);
	errMsg("debug mode enabled");
}
if ($opts{r}) {
	$rename = 1;
	errMsg("rename mode enabled");
	if (defined $opts{b}) {
		$renameFileExt = $opts{b};
	}
	errMsg("backup file ext = $renameFileExt");
}
if ($opts{i}) {
	$inFileExt = $opts{i};
	errMsg("input file extn = $inFileExt");
} else {
	statusErrMsg("fatal", "inputParams"," abort program: input file extn required");
	$paramOK = 0;
}
if ($opts{o}) {
	$outFileExt = $opts{o};
	errMsg("output file ext = $outFileExt");
}
if ($opts{s}) {
	$searchDir = $opts{s};
	errMsg("search directory = $searchDir");
}

errMsg("") if $debug;
dbgMsg("input file extn  = $inFileExt");
dbgMsg("output file extn = $outFileExt");
dbgMsg("backup file extn = $renameFileExt");
dbgMsg("search directory = $searchDir");
if ($rename) {
	dbgMsg("rename mode      = enabled");
} else {
	dbgMsg("rename mode      = disabled");
}

if (!$paramOK) {
	die "\n";
}

errTMsg("processing files");

## check directory
if (opendir(DIR, $searchDir)) {
	# iterate and select required files
	while ( defined ($inFiles = readdir(DIR)) ) {
		dbgMsg("input file1: $inFiles");
		dbgMsg("file extn: " . fileExt($inFiles));
		next unless (fileExt($inFiles) eq $inFileExt);
		$inFile = "$searchDir/$inFiles";
		dbgMsg("input file2: $inFile");
		next unless checkInfile($inFile);

		# check output file
		($outFile, $msg) = createOutfile($inFile, $outFileExt);
		dbgMsg("output file: $outFile");
		if (!$outFile) {
			statusErrMsg("error", "processFile", "skipped: $msg");
			next;
		}

		#process input file
		if ($outFile) {
			# initialise variables, etc
			$total = 0;
			$totalDN = 0;
			open(INF, "<", $inFile) or die "fatal-processFile -- abort program: unexpected problem opening input file $inFile\n";
			open(OUTF, ">", $outFile) or die "fatal-processFile -- abort program: unexpected problem opening output file $outFile\n";

			# process file
			$totalInFile++;
			errMsg("processing input file $inFiles...");

			while(<INF>){
				$total++;
				$cn = revampLine($_);
				if ($cn) {
					$totalDN++;
					print OUTF $cn;
				}
			}
			close(INF);
			close(OUTF);
			if ($rename) {
				if (renInfile($inFile, $renameFileExt)) {
					$totalRenFile++;
				}
			}
			# generate summary statistics
			errMsg(singural($total, " line", " lines") . " read from input file $inFiles");
			if ($totalDN != $total) {
				errMsg(singural($totalDN, " line", " lines") . " written to output file");
			}
		}
	}
	closedir(DIR);
} else {
	statusErrMsg("fatal", "checkDir", "abort program: could not open $searchDir: $!");
	exit 1;
}
if ($totalInFile > 0) {
	if ($totalInFile == $totalRenFile) {
		errMsg(singural($totalInFile, " input file", " input files") . " processed and renamed");
	} elsif ($rename) {
		errMsg(singural($totalInFile, " input file", " input files") . " processed and $totalRenFile renamed");
	} else {
		errMsg(singural($totalInFile, " input file", " input files") . " processed");
	}
}
errTMsg("$progName program terminating normally");
