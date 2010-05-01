#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 3;

use Protocol::OpenID;
use Protocol::OpenID::Extension;

my $ext = Protocol::OpenID::Extension->new(
    name   => 'foo',
    ns     => 'http://foo.com',
    params => {z => [qw/a b/]}
);
is($ext->name, 'foo');
is($ext->ns, 'http://foo.com');
is_deeply($ext->params, {z => 'a,b'});
