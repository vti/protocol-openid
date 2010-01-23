#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 14;

use Protocol::OpenID;
use Protocol::OpenID::Message::VerificationResponse;

my $dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok(!$dir_res->parse(<<'EOF'));
aoo
EOF

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok(!$dir_res->parse(<<'EOF'));
ns:foo
EOF

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok(!$dir_res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
EOF

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok(!$dir_res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
is_valid:1
EOF

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok($dir_res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
is_valid:true
EOF
is($dir_res->ns, OPENID_VERSION_2_0);
ok($dir_res->is_valid);

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok($dir_res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
is_valid:false
EOF
is($dir_res->ns, OPENID_VERSION_2_0);
is($dir_res->is_valid, 'false');

$dir_res = Protocol::OpenID::Message::VerificationResponse->new;
ok($dir_res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
is_valid:false
invalidate_handle:FOO
EOF
is($dir_res->ns, OPENID_VERSION_2_0);
is($dir_res->is_valid, 'false');
is($dir_res->invalidate_handle, 'FOO');
