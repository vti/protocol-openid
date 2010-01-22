#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use Protocol::OpenID;
use Protocol::OpenID::Discovery;

my $d = Protocol::OpenID::Discovery->new;
is_deeply(
    $d->to_hash,
    {   ns                  => OPENID_VERSION_2_0,
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
    }
);

$d = Protocol::OpenID::Discovery->new;
$d->from_hash(
    {   ns          => 'foo',
        op_endpoint => 'bar'
    }
);
is_deeply(
    $d->to_hash,
    {   ns                  => 'foo',
        claimed_identifier  => OPENID_IDENTIFIER_SELECT,
        op_local_identifier => OPENID_IDENTIFIER_SELECT,
        op_endpoint         => 'bar'
    }
);
