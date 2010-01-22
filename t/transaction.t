#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use Protocol::OpenID;
use Protocol::OpenID::Transaction;

my $tx = Protocol::OpenID::Transaction->new;
is_deeply(
    $tx->to_hash,
    {   ns                  => OPENID_VERSION_2_0,
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
    }
);

$tx = Protocol::OpenID::Transaction->new;
$tx->from_hash(
    {   ns          => 'foo',
        op_endpoint => 'bar'
    }
);
is_deeply(
    $tx->to_hash,
    {   ns                  => 'foo',
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
        op_endpoint         => 'bar'
    }
);
