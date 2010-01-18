#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 35;

use_ok('Protocol::OpenID::Association::Response');

my $a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:123
EOF
is($a->error, 'Wrong OpenID 2.0 response');

$a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
EOF
is($a->error, 'Wrong association response');

$a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle: 
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123
EOF
is($a->error, 'Wrong assoc_handle');

$a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
EOF
is($a->error, 'Required dh_server_public and enc_mac_key are missing');

$a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:abc
dh_server_public:123
enc_mac_key:123
EOF
is($a->error, 'Wrong expires_in');

$a = Protocol::OpenID::Association::Response->new;
ok(!$a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:no-encryption
expires_in:100
EOF
is($a->error, 'Required mac_key is missing');

$a = Protocol::OpenID::Association::Response->new;
ok($a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
EOF
is($a->error, 'Sorry');
is($a->session_type, '');
is($a->assoc_type, '');

$a = Protocol::OpenID::Association::Response->new;
$a->parse(<<'EOF');
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256
EOF
is($a->error, 'Sorry');
is($a->session_type, 'DH-SHA256');
is($a->assoc_type, 'HMAC-SHA256');

$a = Protocol::OpenID::Association::Response->new;
ok($a->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123
EOF
ok(!$a->error);
is($a->assoc_handle, 'ABC');
is($a->assoc_type, 'HMAC-SHA1');
is($a->session_type, 'DH-SHA1');
is($a->expires_in, '100');
is($a->dh_server_public, '123');
is($a->enc_mac_key, '123');

$a = Protocol::OpenID::Association::Response->new;
$a->parse(<<'EOF');
assoc_handle:{HMAC-SHA1}{4b537b81}{0QmRNA==}
assoc_type:HMAC-SHA1
dh_server_public:WejxtejU10OB9+/hS6/0iqvIeTBgT7lVNpY1SHl+Dng7tQ78/5u+dK/eAgSStXwymLS6AG2rrVIEWx4cjmWmftTL13TRjkTIWqH5yYHP+bM2UvgYgdusD9HNYIOfWluOamBFZOsTinPtC6BYbPrKt4T8HHBQoqpf0GJdW8e/OiU=
enc_mac_key:CSGk5xSg7AxVmufSjvZRmNLfBtU=
expires_in:1209600
ns:http://specs.openid.net/auth/2.0
session_type:DH-SHA1
EOF
ok(!$a->error);
is($a->assoc_handle, '{HMAC-SHA1}{4b537b81}{0QmRNA==}');
is($a->assoc_type, 'HMAC-SHA1');
is($a->session_type, 'DH-SHA1');
is($a->expires_in, '1209600');
is($a->dh_server_public, 'WejxtejU10OB9+/hS6/0iqvIeTBgT7lVNpY1SHl+Dng7tQ78/5u+dK/eAgSStXwymLS6AG2rrVIEWx4cjmWmftTL13TRjkTIWqH5yYHP+bM2UvgYgdusD9HNYIOfWluOamBFZOsTinPtC6BYbPrKt4T8HHBQoqpf0GJdW8e/OiU=');
is($a->enc_mac_key, 'CSGk5xSg7AxVmufSjvZRmNLfBtU=');
