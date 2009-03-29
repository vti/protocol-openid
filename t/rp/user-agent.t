use Test::More tests => 44;

use_ok('Protocol::OpenID::RP');

use Protocol::OpenID::Discovery;

my $rp = Protocol::OpenID::RP->new(
    return_to => 'http://foo.bar',
    http_req_cb => sub {
        my ($self, $url, $args, $cb) = @_;

        my $status = 200;
        my $res_headers = {};
        my $body;

        if ($url eq 'http://noservices.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://exampleprovider.com/') {
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
        elsif ($url eq 'http://1.0.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://openid.net/signon/1.0</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://1.0-with-delegate.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://openid.net/signon/1.0</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
    <openid:Delegate>https://other.exampleprovider.com/</openid:Delegate>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://1.1.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://openid.net/signon/1.1</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://1.1-with-delegate.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://openid.net/signon/1.1</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
    <openid:Delegate>https://other.exampleprovider.com/</openid:Delegate>
  </Service>
 </XRD>
</xrds:XRDS>

        }
        elsif ($url eq 'http://2.0and1.1.exampleprovider.com/') {
            $res_headers = {'Content-Type' => 'application/xrds+xml'};
            $body = <<'';
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"
   xmlns:openid="http://openid.net/xmlns/1.0">
 <XRD>
  <Service xmlns="xri://$xrd*($v*2.0)">
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
    <Type>http://openid.net/signon/1.1</Type>
    <URI>https://www.exampleprovider.com/endpoint/</URI>
    <LocalID>https://exampleuser.exampleprovider.com/</LocalID>
    <openid:Delegate>https://other.exampleprovider.com/</openid:Delegate>
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
        elsif ($url eq 'http://1.1.html.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" href="https://www.exampleprovider.com/" />
    <link rel="openid.delegate" href="https://html.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://1.1-with-query.html.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" href="https://www.exampleprovider.com/?foo=bar" />
</head>

        }
        elsif ($url eq 'http://1.1.html2.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" href="https://www.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://html2.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider" href="https://www.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://html3.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" rel="openid2.provider" href="https://www.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://html4.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider openid.server" href="https://www.exampleprovider.com/" />
</head>

        }

        $cb->($self => $url =>
              {status => $status, headers => $res_headers, body => $body});
    }
);

$rp->authenticate(
    {openid_identifier => 'noservices.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'error');
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'foo.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply($params,
            {   'openid.ns'         => 'http://specs.openid.net/auth/2.0',
                'openid.mode'       => 'checkid_setup',
                'openid.claimed_id' => 'http://foo.exampleprovider.com/',
                'openid.identity'   => 'https://exampleuser.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply($params,
            {   'openid.ns'   => 'http://specs.openid.net/auth/2.0',
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.identity' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.0.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply(
            $params,
            {   'openid.mode'      => 'checkid_setup',
                'openid.identity'  => 'http://1.0.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.1.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply(
            $params,
            {   'openid.mode'      => 'checkid_setup',
                'openid.identity'  => 'http://1.1.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.1-with-query.html.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/?foo=bar');

        is_deeply(
            $params,
            {   'openid.mode' => 'checkid_setup',
                'openid.identity' =>
                  'http://1.1-with-query.html.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.0-with-delegate.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply(
            $params,
            {   'openid.mode'      => 'checkid_setup',
                'openid.identity'  => 'https://other.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.1-with-delegate.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply(
            $params,
            {   'openid.mode'      => 'checkid_setup',
                'openid.identity'  => 'https://other.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '2.0and1.1.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/endpoint/');

        is_deeply($params,
            {   'openid.ns'   => 'http://specs.openid.net/auth/2.0',
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' => 'http://2.0and1.1.exampleprovider.com/',
                'openid.identity' => 'https://exampleuser.exampleprovider.com/',
                'openid.return_to' => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

# From HTML
$rp->authenticate(
    {openid_identifier => 'html.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.ns'         => 'http://specs.openid.net/auth/2.0',
                'openid.mode'       => 'checkid_setup',
                'openid.claimed_id' => 'http://html.exampleprovider.com/',
                'openid.identity'   => 'https://html.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => 'html2.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.ns'         => 'http://specs.openid.net/auth/2.0',
                'openid.mode'       => 'checkid_setup',
                'openid.claimed_id' => 'http://html2.exampleprovider.com/',
                'openid.identity'   => 'http://html2.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'html3.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.ns'         => 'http://specs.openid.net/auth/2.0',
                'openid.mode'       => 'checkid_setup',
                'openid.claimed_id' => 'http://html3.exampleprovider.com/',
                'openid.identity'   => 'http://html3.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => 'html4.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.ns'         => 'http://specs.openid.net/auth/2.0',
                'openid.mode'       => 'checkid_setup',
                'openid.claimed_id' => 'http://html4.exampleprovider.com/',
                'openid.identity'   => 'http://html4.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);

$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.1.html.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.mode'       => 'checkid_setup',
                'openid.identity'   => 'https://html.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;

$rp->authenticate(
    {openid_identifier => '1.1.html.exampleprovider.com'},
    sub {
        my ($self, $url, $action, $location, $params) = @_;

        is($action, 'redirect');

        is($location, 'https://www.exampleprovider.com/');

        is_deeply($params,
            {   'openid.mode'       => 'checkid_setup',
                'openid.identity'   => 'https://html.exampleprovider.com/',
                'openid.return_to'  => 'http://foo.bar'
            }
        );
    }
);
$rp->clear;


