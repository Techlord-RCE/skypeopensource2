#!/usr/bin/perl
use warnings;

use Win32::API;


$fun = Win32::API->new('C:\\vcnet_proj\\skyauth4_dll\\Debug\\skyauth4_dll.dll','int _sayhello@4(char *lol)') or die $^E;

$lol="My text\0";

$Result = $fun->Call($lol);
print "\n";

#$Result = $fun->Call($lol);
#print "\n";

