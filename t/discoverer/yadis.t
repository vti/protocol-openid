#!/usr/bin/perl

use Test::More;

BEGIN {
    eval "require Protocol::Yadis";
    plan skip_all => 'install Protocol::Yadis to run this test' if $@;
}

plan tests => 6;

use Protocol::OpenID::Discoverer::Yadis;
use Protocol::OpenID::Transaction;

my $http_req_cb = sub {
    my ($url, $method, $headers, $body, $cb) = @_;

    $cb->($url, 200, $headers, $body, "Can't connect");
};

my $tx = Protocol::OpenID::Transaction->new;
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

$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::Yadis->discover(
    $http_req_cb => $tx => sub {
        my $tx = shift;

        is($tx->error, 'No <head> was found');
    }
);

$http_req_cb = sub {
    my ($url, $method, $headers, $body, $cb) = @_;

    my $error;
    $headers = {'Content-Type' => 'application/xrds+xml'};

    $body = <<'EOF';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns:openid="http://openid.net/xmlns/1.0"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD version="2.0">
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
        <Type>http://openid.net/sreg/1.0</Type>
        <Type>http://openid.net/extensions/sreg/1.1</Type>
        <Type>http://schemas.openid.net/pape/policies/2007/06/phishing-resistant</Type>
        <Type>http://openid.net/srv/ax/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <LocalID>http://vti.myopenid.com/</LocalID>
    </Service>
    <Service priority="1">
      <Type>http://openid.net/signon/1.1</Type>
        <Type>http://openid.net/sreg/1.0</Type>
        <Type>http://openid.net/extensions/sreg/1.1</Type>
        <Type>http://schemas.openid.net/pape/policies/2007/06/phishing-resistant</Type>
        <Type>http://openid.net/srv/ax/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://vti.myopenid.com/</openid:Delegate>
    </Service>
    <Service priority="2">
      <Type>http://openid.net/signon/1.0</Type>
        <Type>http://openid.net/sreg/1.0</Type>
        <Type>http://openid.net/extensions/sreg/1.1</Type>
        <Type>http://schemas.openid.net/pape/policies/2007/06/phishing-resistant</Type>
        <Type>http://openid.net/srv/ax/1.0</Type>
      <URI>http://www.myopenid.com/server</URI>
      <openid:Delegate>http://vti.myopenid.com/</openid:Delegate>
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

        ok($tx->ns);
        is($tx->op_endpoint, 'http://www.myopenid.com/server');
    }
);

# OpenID 1.1
$http_req_cb = sub {
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

