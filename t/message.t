#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 11;

use Protocol::OpenID;
use Protocol::OpenID::Message;

my $message = Protocol::OpenID::Message->new;
$message->ns(OPENID_VERSION_2_0);
is_deeply($message->to_hash, {'openid.ns' => OPENID_VERSION_2_0});
is($message->to_string, <<'EOF');
ns:http://specs.openid.net/auth/2.0
EOF

$message = Protocol::OpenID::Message->new;
ok($message->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
EOF
is($message->ns, OPENID_VERSION_2_0);

$message = Protocol::OpenID::Message->new;
ok(!$message->ns);
$message->param(foo => 'bar');
is_deeply($message->to_hash, {'openid.foo' => 'bar'});
is($message->to_string, <<'EOF');
foo:bar
EOF

$message = Protocol::OpenID::Message->new;
ok($message->parse(<<'EOF'));
foo:bar
EOF
ok(!$message->ns);

$message = Protocol::OpenID::Message->new;
$message->from_hash({foo => 'bar'});
is($message->param('foo'), 'bar');
is_deeply($message->to_hash, {'openid.foo' => 'bar'});
