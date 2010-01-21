#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;

use Protocol::OpenID;
use Protocol::OpenID::Association::Request;

my $req = Protocol::OpenID::Association::Request->new;
$req->build;
is($req->ns, OPENID_VERSION_2_0);
is($req->mode, 'associate');
ok($req->is_encrypted);
ok($req->dh_consumer_public);

$req = Protocol::OpenID::Association::Request->new;
$req->session_type('no-encryption');
$req->build;
is($req->ns, OPENID_VERSION_2_0);
is($req->mode, 'associate');
ok(!$req->is_encrypted);
