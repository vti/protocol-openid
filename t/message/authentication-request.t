#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 8;

use Protocol::OpenID;
use Protocol::OpenID::Message::AuthenticationRequest;

# Defaults
my $req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->realm('http://foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_setup',
        'openid.claimed_id' => OPENID_IDENTIFIER_SELECT,
        'openid.identity'   => OPENID_IDENTIFIER_SELECT,
        'openid.realm'      => 'http://foo.bar/'
    }
);

# return_to
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->return_to('http://foo.bar/');
$req->realm('http://foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_setup',
        'openid.claimed_id' => OPENID_IDENTIFIER_SELECT,
        'openid.identity'   => OPENID_IDENTIFIER_SELECT,
        'openid.return_to'  => 'http://foo.bar/',
        'openid.realm'      => 'http://foo.bar/'
    }
);

# claimed_id, but no Local OP Identifier
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->claimed_identifier('http://vti.foo.bar/');
$req->return_to('http://foo.bar/');
$req->realm('http://foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_setup',
        'openid.claimed_id' => 'http://vti.foo.bar/',
        'openid.identity'   => 'http://vti.foo.bar/',
        'openid.return_to'  => 'http://foo.bar/',
        'openid.realm'      => 'http://foo.bar/'
    }
);

# claimed_id and Local OP Identifier
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->claimed_identifier('http://vti.foo.bar/');
$req->op_local_identifier('http://baz.foo.bar/');
$req->realm('http://foo.bar/');
$req->return_to('http://foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_setup',
        'openid.claimed_id' => 'http://vti.foo.bar/',
        'openid.identity'   => 'http://baz.foo.bar/',
        'openid.return_to'  => 'http://foo.bar/',
        'openid.realm'      => 'http://foo.bar/'
    }
);

# Realm
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->claimed_identifier('http://vti.foo.bar/');
$req->op_local_identifier('http://baz.foo.bar/');
$req->realm('http://*.foo.bar/');
$req->return_to('http://foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_setup',
        'openid.claimed_id' => 'http://vti.foo.bar/',
        'openid.identity'   => 'http://baz.foo.bar/',
        'openid.return_to'  => 'http://foo.bar/',
        'openid.realm'      => 'http://*.foo.bar/'
    }
);

# Immediate request
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->claimed_identifier('http://vti.foo.bar/');
$req->op_local_identifier('http://baz.foo.bar/');
$req->realm('http://*.foo.bar/');
$req->return_to('http://foo.bar/');
$req->immediate_request(1);
is_deeply(
    $req->to_hash,
    {   'openid.ns'         => OPENID_VERSION_2_0,
        'openid.mode'       => 'checkid_immediate',
        'openid.claimed_id' => 'http://vti.foo.bar/',
        'openid.identity'   => 'http://baz.foo.bar/',
        'openid.return_to'  => 'http://foo.bar/',
        'openid.realm'      => 'http://*.foo.bar/'
    }
);

# assoc_handle
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->ns(OPENID_VERSION_2_0);
$req->claimed_identifier('http://vti.foo.bar/');
$req->op_local_identifier('http://baz.foo.bar/');
$req->realm('http://*.foo.bar/');
$req->return_to('http://foo.bar/');
$req->assoc_handle('ABC');
is_deeply(
    $req->to_hash,
    {   'openid.ns'           => OPENID_VERSION_2_0,
        'openid.mode'         => 'checkid_setup',
        'openid.claimed_id'   => 'http://vti.foo.bar/',
        'openid.identity'     => 'http://baz.foo.bar/',
        'openid.assoc_handle' => 'ABC',
        'openid.return_to'    => 'http://foo.bar/',
        'openid.realm'        => 'http://*.foo.bar/'
    }
);

# OpenID 1.1 compatibility check
$req = Protocol::OpenID::Message::AuthenticationRequest->new;
$req->claimed_identifier('http://vti.foo.bar/');
$req->op_local_identifier('http://baz.foo.bar/');
$req->return_to('http://foo.bar/');
$req->realm('http://*.foo.bar/');
is_deeply(
    $req->to_hash,
    {   'openid.mode'         => 'checkid_setup',
        'openid.identity'     => 'http://baz.foo.bar/',
        'openid.return_to'    => 'http://foo.bar/',
        'openid.trust_root'   => 'http://*.foo.bar/'
    }
);
