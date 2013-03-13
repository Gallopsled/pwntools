#!/usr/bin/perl

use strict;
use warnings;
use v5.10;
use Switch;
use Cwd;
use File::Copy;

sub decode;
sub unpack;
my  $n = 0;
my  $first_run = 1;

sub main
{
  no warnings 'recursion';
  my @files = @_;
  my $file;
  my $out_files;
  my @out_files;
  my $choice;

  # Usage
  if (@files == 0) {
    say "Usage: unpacker.pl [options] archive[s]";
    exit();
  }

  # Create the unpacking dirs
  if($first_run && -d "unpacked") {
    say "unpacked dir exists, do you want to delete it? [y/N]";
    $choice = <stdin>;
    if($choice =~ /^y/i) {
      `rm -r unpacked`;
    }
    else {
      exit();
    }
  }
  $first_run = 0;

  `mkdir -p unpacked/tmp 2> /dev/null`;

  # Try to unpack each file in the
  foreach $file (@files) {
    push (@out_files, decode($file));
  }


  # Recursively unpack each file that was unpacked
  $out_files = @out_files;
  if ($out_files > 0) {
    main(@out_files);
  }

}

sub decode
{
  my $file = shift;
  say "$file";
  my $type = `file $file`;
  my @out;
  my $not_supported = 0;


  # The main functionality is in this switch-statement.
  # Each case should:
  #   Match the output from file in a logical way
  #   Copy the file to unpacked/$n.$ext
  #   Unpack the file to unpacked/$n/
  #   Add the used tool[s] to dependencies (use apt package names)
  switch($type) {
    case /Zip archive/       { unpacker($file, "zip", "unzip");  }
    case /RAR archive/       { unpacker($file, "rar", "unrar", "e");  }
    case /gzip compressed/   { unpacker($file, "gz", "gunzip");  }
    case /tar archive/       { unpacker($file, "tar", "tar", "xf");  }
    case /XZ compressed/     { unpacker($file, "xz", "unxz");  }
    case /bzip2 compressed/  { unpacker($file, "bz2", "bunzip2");  }
    case /7-zip archive/     { unpacker($file, "7z", "7z", "e");  }
    case /LZMA compressed/   { unpacker($file, "lzma", "unlzma");  }
    case /lzop compressed/   { unpacker($file, "lzop", "lzop", "-d");  }
    case /rzip compressed/   { unpacker($file, "rz", "rzip", "-d");  }
    case /uuencoded/         { unpacker($file, "uu", "uudecode"); }
    case /ARJ archive data/  { unpacker($file, "arj", "arj", "e"); }
    case /ARC archive data/  { unpacker($file, "arc", "arc", "e"); }
    case /LHarc/             { unpacker($file, "lzh", "lha", "e"); }
    case /shell archive/     { unpacker($file, "shar", "unshar"); }
    case /xar archive/       { unpacker($file, "xar", "7z", "e"); }
    case /ACE archive data/  { unpacker($file, "ace", "unace", "e")}
    case /Microsoft Cabinet/ { unpacker($file, "cab", "cabextract")}
    else                     { say "Not supported: $type"; return; }
  }

  # Return all unpacked files and increment $n
  @out = <unpacked/$n/*>;
  $n++;

  return @out;
}

sub unpacker {
  my $file     = shift;
  my $ext      = shift;
  my $unpacker = shift;
  my $flags    = shift // "";


  say "Unpacking $ext archive: $file";

  `mkdir unpacked/$n`;
  copy($file,"unpacked/tmp/$n.$ext");
  copy($file,"unpacked/$n.$ext");
  chdir("unpacked/tmp");
  `$unpacker $flags $n.$ext`;
  chdir("../../");
  unlink("unpacked/tmp/$n.$ext");
  `mv unpacked/tmp/* unpacked/$n/`;
}


chdir(getcwd());
main(@ARGV);
`rmdir unpacked/tmp`;
say "Done!";
