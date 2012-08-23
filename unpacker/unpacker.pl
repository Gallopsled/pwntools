#!/usr/bin/perl

use strict;
use v5.10;
use Switch;
use Cwd;

sub decode;
our $n = 0;

sub main(@)
{
  my @files = @_;
  my $file;
  my $out_files;
  my @out_files;

  # Usage
  if (@files == 0) {
    say "Usage: unpacker.pl [options] archive[s]";
    exit();
  }

  # Create the unpacked dir
  `mkdir unpacked 2> /dev/null`;

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
  my $file = $_[0];
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
    case /Zip archive/  { say "Unpacking zip-archive: $file"; `cp $file unpacked/$n.zip; unzip unpacked/$n.zip -d unpacked/$n/`; }
    else                { say "Not supported: $type"; $not_supported = 1; }
  }


  # Jump out if archive isn't recognized
  if ($not_supported) {
    return;
  }

  # Return all unpacked files and increment $n
  @out = <unpacked/$n/*>;
  $n++;

  return @out;
}


my $cwd = getcwd;
`cd $cwd`;
main(@ARGV);
say "Done!";
