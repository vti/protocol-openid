#!/usr/bin/perl

use Test::More tests => 3;

use Protocol::OpenID::Discoverer::Yadis;
use Protocol::OpenID::Identifier;

my $discoverer = Protocol::OpenID::Discoverer::Yadis->new(
    http_req_cb =>

      sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $headers = {'Content-Type' => 'application/xrds+xml'};

        $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service priority="10">
   <Type>http://openid.net/signon/1.0</Type>
   <URI>http://www.myopenid.com/server</URI>
   <openid:Delegate>http://smoker.myopenid.com/</openid:Delegate>
  </Service>
 </XRD>
</xrds:XRDS>

        $cb->($url, 200, $headers, $body);
    }
);

$discoverer->discover(
    Protocol::OpenID::Identifier->new('foo.com') => sub {
        my ($discoverer, $discovery) = @_;

        ok($discovery);
    }
);

$discoverer->http_req_cb(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $headers = {'Content-Type' => 'application/xrds+xml'};

        $body = 'foo';

        $cb->($url, 200, $headers, $body);
    }
);

$discoverer->discover(
    Protocol::OpenID::Identifier->new('foo.com') => sub {
        my ($discoverer, $discovery) = @_;

        ok(not defined $discovery);
        ok($discoverer->error);
    }
);
