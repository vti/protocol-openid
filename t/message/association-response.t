#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 44;

use Protocol::OpenID::Association;
use Protocol::OpenID::Message::AssociationResponse;

my $a = Protocol::OpenID::Association->new;
my $res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:123
EOF
is($res->error, 'Wrong OpenID 2.0 response');

$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
EOF
is($res->error, 'Wrong association response');

$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle: 
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123
EOF
is($res->error, 'Wrong assoc_handle');

$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
EOF
is($res->error, 'Required dh_server_public and enc_mac_key are missing');

$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:abc
dh_server_public:123
enc_mac_key:123
EOF
is($res->error, 'Wrong expires_in');

$a = Protocol::OpenID::Association->new(session_type => 'no-encryption');
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:no-encryption
expires_in:100
EOF
is($res->error, 'Required mac_key is missing');

$a = Protocol::OpenID::Association->new;
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok($res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
EOF
is($res->param('error'), 'Sorry');
is($a->error, 'Sorry');
ok(not defined $res->session_type);
ok(not defined $res->assoc_type);

$a = Protocol::OpenID::Association->new;
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
$res->parse(<<'EOF');
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256
EOF
is($res->param('error'), 'Sorry');
is($a->error, 'Sorry');
is($res->session_type, 'DH-SHA256');
is($res->assoc_type, 'HMAC-SHA256');

$a = Protocol::OpenID::Association->new;
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok(!$res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA256
session_type:DH-SHA256
expires_in:100
dh_server_public:123
enc_mac_key:123
EOF
is($res->error, 'Wrong association response');

$a = Protocol::OpenID::Association->new;
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
ok($res->parse(<<'EOF'));
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123
EOF
ok(!$res->error);
is($res->assoc_handle, 'ABC');
is($res->assoc_type, 'HMAC-SHA1');
is($res->session_type, 'DH-SHA1');
is($res->expires_in, '100');
is($res->dh_server_public, '123');
is($res->enc_mac_key, '123');
is($a->assoc_handle, 'ABC');
is($a->assoc_type, 'HMAC-SHA1');
is($a->session_type, 'DH-SHA1');
is($a->expires_in, '100');
is($a->dh_server_public, '123');
is($a->enc_mac_key, '123');

$a = Protocol::OpenID::Association->new;
$res = Protocol::OpenID::Message::AssociationResponse->new($a);
$res->parse(<<'EOF');
assoc_handle:{HMAC-SHA1}{4b537b81}{0QmRNA==}
assoc_type:HMAC-SHA1
dh_server_public:WejxtejU10OB9+/hS6/0iqvIeTBgT7lVNpY1SHl+Dng7tQ78/5u+dK/eAgSStXwymLS6AG2rrVIEWx4cjmWmftTL13TRjkTIWqH5yYHP+bM2UvgYgdusD9HNYIOfWluOamBFZOsTinPtC6BYbPrKt4T8HHBQoqpf0GJdW8e/OiU=
enc_mac_key:CSGk5xSg7AxVmufSjvZRmNLfBtU=
expires_in:1209600
ns:http://specs.openid.net/auth/2.0
session_type:DH-SHA1
EOF
ok(!$res->error);
is($res->assoc_handle, '{HMAC-SHA1}{4b537b81}{0QmRNA==}');
is($res->assoc_type, 'HMAC-SHA1');
is($res->session_type, 'DH-SHA1');
is($res->expires_in, '1209600');
is($res->dh_server_public, 'WejxtejU10OB9+/hS6/0iqvIeTBgT7lVNpY1SHl+Dng7tQ78/5u+dK/eAgSStXwymLS6AG2rrVIEWx4cjmWmftTL13TRjkTIWqH5yYHP+bM2UvgYgdusD9HNYIOfWluOamBFZOsTinPtC6BYbPrKt4T8HHBQoqpf0GJdW8e/OiU=');
is($res->enc_mac_key, 'CSGk5xSg7AxVmufSjvZRmNLfBtU=');
