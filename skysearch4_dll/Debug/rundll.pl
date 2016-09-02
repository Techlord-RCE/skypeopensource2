#!/usr/bin/perl
use warnings;

use Encode;
use Win32::API;


#$fun = Win32::API->new('C:\\vcnet_proj\\skysearch4_dll\\Debug\\skysearch4_dll.dll','int _skysearch_one(char *username, char *vcard_buf, int maxlen)') or die $^E;
#$fun = Win32::API->new('C:\\vcnet_proj\\skysearch4_dll\\Debug\\skysearch4_dll.dll','int _skysearch_many(int argc, char *argv[], char *vcard_buf, int maxlen)') or die $^E;

$fun = Win32::API->new('C:\\vcnet_proj\\skysearch4_dll\\Debug\\skysearch4_dll.dll','int _skysearch_getslots@12(int argc, char *argv[], char *myip)') or die $^E;

$argc = 2;
$argv = encode_utf8("themagicforyou\0");
$argv.= encode_utf8("notnowagainplease\0");

$argv2 = encode_utf8("themagicforyou\0");
$argv3 = " "x100;

#$argv2[1] = encode_utf8("themagicforyou\0");
#$argv2[2] = encode_utf8("\0");

$Result = $fun->Call($argc, $argv2, $argv3);

print "\n";
