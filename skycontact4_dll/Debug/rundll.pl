#!/usr/bin/perl
use warnings;

use Encode;
use Win32::API;


$fun = Win32::API->new('C:\\vcnet_proj\\skycontact4_dll\\Debug\\skycontact4_dll.dll','int _skycontact@8(char *username, char *password)') or die $^E;

$user = encode_utf8("themagicforyou\0");
$pass = encode_utf8("adf123\0");

$Result = $fun->Call(\$user, \$pass);
print "\n";

