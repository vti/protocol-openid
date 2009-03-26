use Test::More tests => 9;

use_ok('Protocol::OpenID::RP');

my $rp = Protocol::OpenID::RP->new(
    return_to => 'http://foo.bar',
    http_req_cb => sub {
        my ($self, $url, $args, $cb) = @_;

        my $status = 200;
        my $res_headers = {};
        my $body;

        if ($url eq 'http://exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://specs.openid.net/auth/2.0/server</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://foo.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
    <LocalID>https://exampleuser.exampleprovider.com/</LocalID>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://html.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider" href="https://www.exampleprovider.com/" />
    <link rel="openid2.local_id" href="https://html.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://html2.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider" href="https://www.exampleprovider.com/" />
</head>

        }

        $cb->($self => $url =>
              {status => $status, headers => $res_headers, body => $body});
    }
);

$rp->authenticate(
    {openid_identifier => 'foo.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'redirect');

        is( $location,
            'https://www.exampleprovider.com/endpoint/?'
              . 'openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&'
              . 'openid.mode=checkid_setup&'
              . 'openid.claimed_id=http%3A%2F%2Ffoo.exampleprovider.com%2F&'
              . 'openid.identity=https%3A%2F%2Fexampleuser.exampleprovider.com%2F&'
              . 'openid.return_to=http%3A%2F%2Ffoo.bar',
            'Claimed Identifier'
        );
    }
);

$rp->clear;

# From HTML
$rp->authenticate(
    {openid_identifier => 'html.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'redirect');

        is( $location,
            'https://www.exampleprovider.com/?'
              . 'openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&'
              . 'openid.mode=checkid_setup&'
              . 'openid.claimed_id=http%3A%2F%2Fhtml.exampleprovider.com%2F&'
              . 'openid.identity=https%3A%2F%2Fhtml.exampleprovider.com%2F&'
              . 'openid.return_to=http%3A%2F%2Ffoo.bar',
            'Claimed Identifier'
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'html2.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'redirect');

        is( $location,
            'https://www.exampleprovider.com/?'
              . 'openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&'
              . 'openid.mode=checkid_setup&'
              . 'openid.claimed_id=http%3A%2F%2Fhtml2.exampleprovider.com%2F&'
              . 'openid.identity=http%3A%2F%2Fhtml2.exampleprovider.com%2F&'
              . 'openid.return_to=http%3A%2F%2Ffoo.bar',
            'Claimed Identifier'
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'redirect');

        is( $location,
            'https://www.exampleprovider.com/endpoint/?'
              . 'openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&'
              . 'openid.mode=checkid_setup&'
              . 'openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&'
              . 'openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&'
              . 'openid.return_to=http%3A%2F%2Ffoo.bar',
            'OP Identifier'
        );
    }
);
