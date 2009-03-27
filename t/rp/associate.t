use Test::More tests => 24;

use Protocol::OpenID::RP;
use Protocol::OpenID::Association;

my $rp = Protocol::OpenID::RP->new(
    return_to   => '/dev/null',
    http_req_cb => sub {
        my ($self, $url, $args, $cb) = @_;

        my $status = 200;
        my $body;

        if ($url eq 'http://stupid-provider.com/') {
            $body =<<'';
ns:123

        }
        elsif ($url eq 'http://stupid-provider2.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0

        }
        elsif ($url eq 'http://stupid-provider3.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle: 
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123

        }
        elsif ($url eq 'http://stupid-provider4.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100

        }
        elsif ($url eq 'http://stupid-provider5.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:abc
dh_server_public:123
enc_mac_key:123

        }
        elsif ($url eq 'http://stupid-provider6.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:no-encryption
expires_in:100

        }
        elsif ($url eq 'http://error-provider.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type

        }
        elsif ($url eq 'http://retry-provider.com/') {
            if ($args->{params}->{'openid.session_type'} ne 'DH-SHA256') {
                $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256

            }
            else {
                $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA256
session_type:DH-SHA256
expires_in:100
dh_server_public:123
enc_mac_key:123

            }
        }
        elsif ($url eq 'http://recursive-retry-provider.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
error:Sorry
error_code:unsupported-type
session_type:DH-SHA256
assoc_type:HMAC-SHA256

        }
        elsif ($url eq 'http://successful-response.com/') {
            $body =<<'';
ns:http://specs.openid.net/auth/2.0
assoc_handle:ABC
assoc_type:HMAC-SHA1
session_type:DH-SHA1
expires_in:100
dh_server_public:123
enc_mac_key:123

        }

        $cb->($self => $url =>
              {status => $status, headers => $headers, body => $body});
    }
);

$rp->_associate(
    'http://foo' => sub {
        my ($self, $result) = @_;
        is($result, 'skip');
    }
);

$rp->store_cb(sub { my ($key, $hashref) = @_ });

$rp->_associate(
    'http://stupid-provider.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Wrong OpenID 2.0 response');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://stupid-provider2.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Wrong association response');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://stupid-provider2.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Wrong association response');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://stupid-provider3.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Wrong assoc_handle');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://stupid-provider4.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Required dh_server_public and enc_mac_key are missing');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://stupid-provider5.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Wrong expires_in');
        is($result, 'error');
    }
);

$rp->association->session_type('no-encryption');
$rp->_associate(
    'http://stupid-provider6.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Required mac_key is missing');
        is($result, 'error');
    }
);
$rp->association(Protocol::OpenID::Association->new);

$rp->_associate(
    'http://error-provider.com/' => sub {
        my ($self, $result) = @_;
        is($self->error, 'Sorry');
        is($result, 'error');
    }
);

$rp->_associate(
    'http://retry-provider.com/' => sub {
        my ($self, $result) = @_;
        is($result, 'ok');
    }
);
is($rp->association->assoc_type, 'HMAC-SHA256');
is($rp->association->session_type, 'DH-SHA256');

$rp->_associate(
    'http://recursive-retry-provider.com/' => sub {
        my ($self, $result) = @_;
        is($result, 'error');
    }
);
is($rp->association->assoc_type, 'HMAC-SHA256');
is($rp->association->session_type, 'DH-SHA256');

$rp->association(Protocol::OpenID::Association->new);
$rp->_associate(
    'http://successful-response.com/' => sub {
        my ($self, $result) = @_;
        is($result, 'ok');
    }
);
