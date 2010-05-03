#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 6;

use Protocol::OpenID;
use Protocol::OpenID::Transaction;

my $tx = Protocol::OpenID::Transaction->new;
$tx->ns(OPENID_VERSION_2_0);
is_deeply(
    $tx->to_hash,
    {   state               => 'init',
        ns                  => OPENID_VERSION_2_0,
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
    }
);

$tx = Protocol::OpenID::Transaction->new;
$tx->from_hash(
    {   state       => 'init',
        ns          => 'foo',
        op_endpoint => 'bar'
    }
);
is_deeply(
    $tx->to_hash,
    {   state               => 'init',
        ns                  => 'foo',
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
        op_endpoint         => 'bar'
    }
);

$tx = Protocol::OpenID::Transaction->new;
is_deeply($tx->to_hash, {state => 'init'});

is($tx->state, 'init');
$tx->state_cb(sub { ok(1) });
$tx->state('foo');
is($tx->state, 'foo');
