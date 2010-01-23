#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 11;

use Protocol::OpenID;
use Protocol::OpenID::Message;

my $message = Protocol::OpenID::Message->new(z => 'a');
$message->ns(OPENID_VERSION_2_0);
$message->param(zoo => 'bar');
$message->param(a => 'b');
is_deeply(
    $message->to_hash,
    {   'openid.z'   => 'a',
        'openid.ns'  => OPENID_VERSION_2_0,
        'openid.zoo' => 'bar',
        'openid.a'   => 'b'
    }
);
is($message->to_string, <<'EOF');
z:a
ns:http://specs.openid.net/auth/2.0
zoo:bar
a:b
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
