#!/usr/bin/perl
use warnings;

use Encode;
use Win32::API;


$fun = Win32::API->new('C:\\vcnet_proj\\skyrelay4_dll\\Debug\\skyrelay4_dll.dll','int _skyrelay@16(char *myip, char *remote_name, char *vcard, char *output)') or die $^E;

$myip = encode_utf8("78.81.150.182\0");
$remote_name = encode_utf8("agregatore\0");
$vcard = encode_utf8("0x7e0d88a62c69f917-s-s157.55.130.174:40017-r0.0.0.0:0-l0.0.0.0:0\0");
$output = " "x1000; 
$output.= "\0";

$Result = $fun->Call($myip, $remote_name, $vcard, $output);
print "\n";

