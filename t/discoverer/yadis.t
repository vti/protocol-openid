#!/usr/bin/perl

use Test::More;

BEGIN {
    eval "require Protocol::Yadis";
    plan skip_all => 'install Protocol::Yadis to run this test' if $@;
}

plan tests => 4;

use Protocol::OpenID::Discoverer::Yadis;
use Protocol::OpenID::Transaction;

my $tx = Protocol::OpenID::Transaction->new;

my $http_req_cb = sub {
    my ($url, $method, $headers, $body, $cb) = @_;

    my $error;
    $headers = {'Content-Type' => 'application/xrds+xml'};

    $body = <<'EOF';
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
EOF

    $cb->($url, 200, $headers, $body, $error);
};

$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::Yadis->discover(
    $http_req_cb => $tx => sub {
        my $tx = shift;

        ok(!$tx->ns);
        is($tx->op_endpoint, 'http://www.myopenid.com/server');
    }
);

$http_req_cb = sub {
    my ($url, $method, $headers, $body, $cb) = @_;

    $cb->($url, 200, $headers, $body, "Can't connect");
};

Protocol::OpenID::Discoverer::Yadis->discover(
    $http_req_cb => $tx => sub {
        my $tx = shift;

        is($tx->error, "Can't connect");
    }
);

$http_req_cb = sub {
    my ($url, $method, $headers, $body, $cb) = @_;

    $headers = {'Content-Type' => 'application/xrds+xml'};

    $body = 'foo';

    $cb->($url, 200, $headers, $body);
};

Protocol::OpenID::Discoverer::Yadis->discover(
    $http_req_cb => $tx => sub {
        my $tx = shift;

        is($tx->error, 'No <head> was found');
    }
);
