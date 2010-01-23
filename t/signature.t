#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 2;

use Protocol::OpenID::Signature;

my $s = Protocol::OpenID::Signature->new(
    {   'openid.response_nonce' => '2010-01-23T20:49:44ZlHip11',
        'openid.mode'           => 'id_res',
        'openid.claimed_id'     => 'http://vti.myopenid.com/',
        'openid.assoc_handle'   => '{HMAC-SHA1}{4b5b60e1}{Gf+xYg==}',
        'openid.ns'             => 'http://specs.openid.net/auth/2.0',
        'openid.signed' =>
          'assoc_handle,claimed_id,identity,mode,ns,op_endpoint,response_nonce,return_to,signed',
        'openid.sig'         => 'fxtNcegkjKNGMpOGTSgzTJscDP8=',
        'openid.op_endpoint' => 'http://www.myopenid.com/server',
        'openid.identity'    => 'http://vti.myopenid.com/',
        'openid.return_to'   => 'http://dell:3000/'
    }
);

is_deeply(
    [$s->keys],
    [   qw/
          assoc_handle
          claimed_id
          identity
          mode
          ns
          op_endpoint
          response_nonce
          return_to
          signed
          /
    ]
);
is($s->calculate('7A/8TxQlJsJla2MP7ZHBHOgr59A='),
    'fxtNcegkjKNGMpOGTSgzTJscDP8=');
