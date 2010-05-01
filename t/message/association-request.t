#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 7;

use Protocol::OpenID;
use Protocol::OpenID::Association;
use Protocol::OpenID::Message::AssociationRequest;

my $a = Protocol::OpenID::Association->new;
my $req = Protocol::OpenID::Message::AssociationRequest->new($a);
$req->ns(OPENID_VERSION_2_0);
$req->build;
is($req->ns, OPENID_VERSION_2_0);
is($req->mode, 'associate');
ok($req->is_encrypted);
ok($req->dh_consumer_public);

$a = Protocol::OpenID::Association->new(session_type => 'no-encryption');
$req = Protocol::OpenID::Message::AssociationRequest->new($a);
$req->ns(OPENID_VERSION_2_0);
$req->build;
is($req->ns, OPENID_VERSION_2_0);
is($req->mode, 'associate');
ok(!$req->is_encrypted);
