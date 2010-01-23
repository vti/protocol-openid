#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use Protocol::OpenID::RP;

my $rp = Protocol::OpenID::RP->new;

$rp->cache_get_cb->(
    "foo" => sub {
        my $cache = shift;

        ok(!$cache);
    }
);

$rp->cache_set_cb->(
    "foo" => {hello => 'world'} => sub {
    }
);

$rp->cache_get_cb->(
    "foo" => sub {
        my $cache = shift;

        is($cache->{hello}, 'world');
    }
);
