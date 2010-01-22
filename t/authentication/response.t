#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 42;

use Protocol::OpenID;
use Protocol::OpenID::Nonce;
use Protocol::OpenID::Authentication::Response;

my $current_nonce = Protocol::OpenID::Nonce->new;

my $res = Protocol::OpenID::Authentication::Response->new;
ok( $res->from_hash(
        {   'openid.ns'   => OPENID_VERSION_2_0,
            'openid.mode' => 'setup_needed'
        }
    )
);
is($res->mode, 'setup_needed');
is_deeply(
    $res->to_hash,
    {   'openid.ns'   => OPENID_VERSION_2_0,
        'openid.mode' => 'setup_needed',
    }
);
ok($res->is_setup_needed);

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'   => OPENID_VERSION_2_0,
            'openid.mode' => 'user_setup_url'
        }
    )
);
ok($res->is_error);
is($res->error, 'Unknown mode');

$res = Protocol::OpenID::Authentication::Response->new;
ok($res->from_hash({'openid.mode' => 'user_setup_url'}));
is($res->mode, 'user_setup_url');
ok($res->is_setup_needed);
ok($res->is_user_setup_url);

$res = Protocol::OpenID::Authentication::Response->new;
ok( $res->from_hash(
        {   'openid.ns'   => OPENID_VERSION_2_0,
            'openid.mode' => 'cancel'
        }
    )
);
is($res->mode, 'cancel');
ok($res->is_canceled);

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'   => OPENID_VERSION_2_0,
            'openid.mode' => 'id_res'
        },
    )
);
ok($res->is_error);
is($res->error, 'Return to is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'        => OPENID_VERSION_2_0,
            'openid.mode'      => 'id_res',
            'openid.return_to' => 'http://foo.com/',
        },
    )
);
ok($res->is_error);
is($res->error, 'OP Endpoint is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'          => OPENID_VERSION_2_0,
            'openid.mode'        => 'id_res',
            'openid.return_to'   => 'http://foo.com/',
            'openid.op_endpoint' => 'http://myserverprovider.com/',
        },
    )
);
ok($res->is_error);
is($res->error, 'Nonce is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.response_nonce' => '2000-12-12T12:12:12ZHELLO'
        },
    )
);
ok($res->is_error);
is($res->error, 'Nonce is too old');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.response_nonce' => '2029-12-12T12:12:12ZHELLO'
        },
    )
);
ok($res->is_error);
is($res->error, 'Nonce is in the future');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.response_nonce' => $current_nonce,
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.claimed_id'     => 'http://user.myserverprovider.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
        }
    )
);
ok($res->is_error);
is($res->error, 'Association handle is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.response_nonce' => $current_nonce,
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.claimed_id'     => 'http://user.myserverprovider.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.assoc_handle'   => 'FOO'
        }
    )
);
ok($res->is_error);
is($res->error, 'Signed is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( !$res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.response_nonce' => $current_nonce,
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.claimed_id'     => 'http://user.myserverprovider.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.assoc_handle'   => 'FOO',
            'openid.signed'         => 'foo',
        }
    )
);
ok($res->is_error);
is($res->error, 'Sig is missing');

$res = Protocol::OpenID::Authentication::Response->new;
ok( $res->from_hash(
        {   'openid.ns'             => OPENID_VERSION_2_0,
            'openid.mode'           => 'id_res',
            'openid.return_to'      => 'http://foo.com/',
            'openid.identity'       => 'http://user.myserverprovider.com/',
            'openid.response_nonce' => $current_nonce,
            'openid.op_endpoint'    => 'http://myserverprovider.com/',
            'openid.claimed_id'     => 'http://user.myserverprovider.com/',
            'openid.assoc_handle'   => 'FOO',
            'openid.signed'         => 'foo',
            'openid.sig'            => 'bar'
        }
    )
);
is($res->mode, 'id_res');
ok($res->is_success);

is_deeply(
    $res->to_hash,
    {   'openid.ns'             => OPENID_VERSION_2_0,
        'openid.mode'           => 'id_res',
        'openid.return_to'      => 'http://foo.com/',
        'openid.response_nonce' => $current_nonce,
        'openid.op_endpoint'    => 'http://myserverprovider.com/',
        'openid.claimed_id'     => 'http://user.myserverprovider.com/',
        'openid.identity'       => 'http://user.myserverprovider.com/',
        'openid.assoc_handle'   => 'FOO',
        'openid.signed'         => 'foo',
        'openid.sig'            => 'bar'
    }
);
