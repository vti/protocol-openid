#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 1;

use Protocol::OpenID;
use Protocol::OpenID::Nonce;
use Protocol::OpenID::Message::AuthenticationResponse;
use Protocol::OpenID::Message::VerificationRequest;

my $current_nonce = Protocol::OpenID::Nonce->new->to_string;

my $res = Protocol::OpenID::Message::AuthenticationResponse->new;
$res->from_hash(
    {   'openid.ns'             => OPENID_VERSION_2_0,
        'openid.mode'           => 'id_res',
        'openid.return_to'      => 'http://foo.com/',
        'openid.identity'       => 'http://user.myserverprovider.com/',
        'openid.response_nonce' => $current_nonce,
        'openid.op_endpoint'    => 'http://myserverprovider.com/',
        'openid.claimed_id'     => 'http://user.myserverprovider.com/',
        'openid.signed'         => 'foo',
        'openid.sig'            => 'bar'
    }
);

my $dir_req = Protocol::OpenID::Message::VerificationRequest->new($res);
is_deeply($dir_req->to_hash,
    {%{$res->to_hash}, 'openid.mode' => 'check_authentication'});
