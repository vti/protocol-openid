#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 17;

use Protocol::OpenID::Parameters;

my $p = Protocol::OpenID::Parameters->new;
is_deeply($p->params, []);

$p->param(foo => 'bar');
$p->params([]);
is_deeply($p->params, []);

$p->param(ns => 'foo');
is($p->params->[0], 'openid.ns');
is($p->params->[1], 'foo');
is($p->param('ns'), 'foo');

$p->param(ns => 'bar');
is($p->params->[0], 'openid.ns');
is($p->params->[1], 'bar');
is($p->param('ns'), 'bar');

$p->params([]);
$p->param(foo => 'bar');
$p->param(baz => 'foo');

is_deeply($p->to_hash, {'foo' => 'bar', 'baz' => 'foo'});
is_deeply($p->to_hash(prefixed => 1),
    {'openid.foo' => 'bar', 'openid.baz' => 'foo'});

$p = Protocol::OpenID::Parameters->new('ns:http://specs.openid.net/auth/2.0');
is($p->param('ns'), 'http://specs.openid.net/auth/2.0');

$p->params([]);
$p->parse();
is_deeply($p->params, []);

$p->params([]);
$p->parse('');
is_deeply($p->params, []);

$p->parse(<<'EOF');
ns:http://specs.openid.net/auth/2.0
error:hello
EOF

is($p->param('ns'),    'http://specs.openid.net/auth/2.0');
is($p->param('error'), 'hello');

is($p->to_string, "ns:http://specs.openid.net/auth/2.0\nerror:hello\n");

$p->params([]);
$p->param(foo => 'bar');
$p->parse(<<'EOF');
nsbar
error:hello
EOF

is_deeply($p->params, []);
