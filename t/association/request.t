#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 4;

use_ok('Protocol::OpenID::Association::Request');

my $a = Protocol::OpenID::Association::Request->new;
ok($a->is_encrypted);
ok($a->dh_consumer_public);

$a = Protocol::OpenID::Association::Request->new;
$a->session_type('no-encryption');
ok(!$a->is_encrypted);
