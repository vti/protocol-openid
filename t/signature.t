#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use Protocol::OpenID::Signature;

my $params = {
    'openid.response_nonce' => '2009-03-29T22:26:35Z0610',
    'openid.mode'           => 'id_res',
    'openid.claimed_id'     => 'http://foo.bar.net/',
    'openid.assoc_handle'   => '19eaef2af65153',
    'openid.ns'             => 'http://specs.openid.net/auth/2.0',
    'openid.signed' =>
      'op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle,mode',
    'openid.sig'         => 'UitMYFUDpzp08DEqVaJhB/lpPQlqnxRo2jJyADX6H0M=',
    'openid.op_endpoint' => 'http://bar.net/server',
    'openid.identity'    => 'http://foo.bar.net/',
    'openid.return_to'   => 'http://myserver.com/'
};

my $s = Protocol::OpenID::Signature->new($params);

is_deeply(
    [$s->keys],
    [   qw/op_endpoint
          claimed_id
          identity
          return_to
          response_nonce
          assoc_handle
          mode/
    ]
);

my $signature = $s->calculate('secret');
is(length $signature, 160 / 8);
