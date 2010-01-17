#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 30;

use_ok('Protocol::OpenID::Association');

my $a = Protocol::OpenID::Association->new;

ok($a->is_encrypted);
ok($a->is_expired);
ok($a->dh_consumer_public);

$a->session_type('no-encryption');
ok(!$a->is_encrypted);

$a->expires(time - 2);
ok($a->is_expired);

$a->expires(time + 2);
ok(!$a->is_expired);

ok(not defined $a->dh_consumer_public);

my $http_req_cb = sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        my $status = 200;

        if ($url eq 'http://stupid-provider.com/') {
            $body =<<'';
ns:123

        }
        elsif ($url eq 'http://stupid-provider2.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0

        }
        elsif ($url eq 'http://stupid-provider3.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle: 
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123

        }
        elsif ($url eq 'http://stupid-provider4.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100

        }
        elsif ($url eq 'http://stupid-provider5.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:abc
dh_server_public:123
enc_mac_key:123

        }
        elsif ($url eq 'http://stupid-provider6.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:no-encryption
expires_in:100

        }
        elsif ($url eq 'http://error-provider.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type

        }
        elsif ($url eq 'http://retry-provider.com/') {
            if ($body->{'openid.session_type'} ne 'DH-SHA256') {
                $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256

            }
            else {
                $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA256
session_type:DH-SHA256
expires_in:100
dh_server_public:123
enc_mac_key:123

            }
        }
        elsif ($url eq 'http://recursive-retry-provider.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256

        }
        elsif ($url eq 'http://successful-response.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123

        }
        elsif ($url eq 'http://successful-real-life-response.com/') {
            $body = <<'EOF';
assoc_handle:{HMAC-SHA1}{4b537b81}{0QmRNA==}
assoc_type:HMAC-SHA1
dh_server_public:WejxtejU10OB9+/hS6/0iqvIeTBgT7lVNpY1SHl+Dng7tQ78/5u+dK/eAgSStXwymLS6AG2rrVIEWx4cjmWmftTL13TRjkTIWqH5yYHP+bM2UvgYgdusD9HNYIOfWluOamBFZOsTinPtC6BYbPrKt4T8HHBQoqpf0GJdW8e/OiU=
enc_mac_key:CSGk5xSg7AxVmufSjvZRmNLfBtU=
expires_in:1209600
ns:http://specs.openid.net/auth/2.0
session_type:DH-SHA1
EOF
        }
        else {
            $status = 404;
        }

        $cb->($url, $status, $headers, $body);
};

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://successful-real-life-response.com/' => sub {
        my $self = shift;

        ok(!$self->error);
        ok($self->is_associated);
        ok(!$self->is_expired);
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Wrong OpenID 2.0 response');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider2.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Wrong association response');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider2.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Wrong association response');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider3.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Wrong assoc_handle');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider4.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Required dh_server_public and enc_mac_key are missing');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://stupid-provider5.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Wrong expires_in');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->session_type('no-encryption');
$a->associate(
    'http://stupid-provider6.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Required mac_key is missing');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://error-provider.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Sorry');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://retry-provider.com/' => sub {
        my ($self) = @_;

        ok($self->is_associated);
        ok(!$self->error);
        ok(!$self->is_expired);
        is($self->assoc_type, 'HMAC-SHA256');
        is($self->session_type, 'DH-SHA256');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://recursive-retry-provider.com/' => sub {
        my ($self) = @_;

        is($self->error, 'Sorry');
        is($a->assoc_type, 'HMAC-SHA256');
        is($a->session_type, 'DH-SHA256');
    }
);

$a = Protocol::OpenID::Association->new(http_req_cb => $http_req_cb);
$a->associate(
    'http://successful-response.com/' => sub {
        my ($self) = @_;

        ok($self->is_associated);
        ok(!$self->error);
        ok(!$self->is_expired);
    }
);
