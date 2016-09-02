#!/usr/bin/perl
use warnings;

use Encode;
use Win32::API;

$fpath = 'C:\\vcnet_proj\\goodsendrelay4_dll\\Debug\\goodsendrelay4_dll.dll';

$fun = Win32::API->new($fpath,'int _relaysend@16(char* static_myip, char* static_username, char* static_uservcard, char* static_msg)') or die $^E;

$myip = encode_utf8("117.3.37.199\0");
$username = encode_utf8("themagicforyou\0");
$uservcard = encode_utf8("0xe03e31ae403ae012-s-s65.55.223.25:40021-r95.52.236.102:57608-l192.168.1.75:57608\0");
$msg = encode_utf8("This is skype msg, again.\0");

$Result = $fun->Call($myip, $username, $uservcard, $msg);
print "\n";

