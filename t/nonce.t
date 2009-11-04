#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 13;

use_ok('Protocol::OpenID::Nonce');

my $nonce = Protocol::OpenID::Nonce->new;

ok($nonce->parse());
ok(not defined $nonce->epoch);
ok($nonce->parse(''));
ok(not defined $nonce->epoch);
ok($nonce->parse('foo bar'));
ok(not defined $nonce->epoch);

ok($nonce->parse('2009-03-23T14:40:38ZUNIQUE'));

is($nonce->epoch, '1237819238');
is($nonce->tail,  'UNIQUE');

is("$nonce", '2009-03-23T14:40:38ZUNIQUE');

$nonce = Protocol::OpenID::Nonce->new(1237819238);
$nonce->tail('ABCD');
is("$nonce", '2009-03-23T14:40:38ZABCD');

$nonce->parse();
ok(not defined $nonce->epoch);
