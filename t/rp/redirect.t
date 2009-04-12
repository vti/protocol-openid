use Test::More tests => 8;

use Protocol::OpenID::RP;
use Protocol::OpenID::Discovery;
use Protocol::OpenID::Association;

my $sub = \&Protocol::OpenID::RP::_redirect;

my $rp = Protocol::OpenID::RP->new(http_req_cb => sub { });

my $discovery = Protocol::OpenID::Discovery->new;

$rp->discovery($discovery);

# Defaults
$rp->realm('http://foo.bar');
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.identity' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.realm' => 'http://foo.bar/'
            }
        );
    }
);

# return_to
$rp->return_to('http://foo.bar');
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.identity' =>
                  'http://specs.openid.net/auth/2.0/identifier_select',
                'openid.return_to' => 'http://foo.bar/',
                'openid.realm'     => 'http://foo.bar/'
            }
        );
    }
);

# claimed_id, but no Local OP Identifier
$discovery->claimed_identifier('http://vti.foo.bar/');
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' => 'http://vti.foo.bar/',
                'openid.identity'   => 'http://vti.foo.bar/',
                'openid.return_to'  => 'http://foo.bar/',
                'openid.realm'      => 'http://foo.bar/'
            }
        );
    }
);

# claimed_id and Local OP Identifier
$discovery->claimed_identifier('http://vti.foo.bar/');
$discovery->op_local_identifier('http://baz.foo.bar/');
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' => 'http://vti.foo.bar/',
                'openid.identity'   => 'http://baz.foo.bar/',
                'openid.return_to'  => 'http://foo.bar/',
                'openid.realm'      => 'http://foo.bar/'
            }
        );
    }
);

# realm
$rp->realm('http://*.foo.bar');
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id' => 'http://vti.foo.bar/',
                'openid.identity'   => 'http://baz.foo.bar/',
                'openid.return_to'  => 'http://foo.bar/',
                'openid.realm'      => 'http://*.foo.bar/'
            }
        );
    }
);

# Immediate request
$rp->immediate_request(1);
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_immediate',
                'openid.claimed_id' => 'http://vti.foo.bar/',
                'openid.identity'   => 'http://baz.foo.bar/',
                'openid.return_to'  => 'http://foo.bar/',
                'openid.realm'      => 'http://*.foo.bar/'
            }
        );
    }
);
$rp->immediate_request(0);

# assoc_handle
my $association = Protocol::OpenID::Association->new;
$association->assoc_handle('ABC');
$rp->association($association);
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.ns'   => $Protocol::OpenID::Discovery::VERSION_2_0,
                'openid.mode' => 'checkid_setup',
                'openid.claimed_id'   => 'http://vti.foo.bar/',
                'openid.identity'     => 'http://baz.foo.bar/',
                'openid.assoc_handle' => 'ABC',
                'openid.return_to'    => 'http://foo.bar/',
                'openid.realm'        => 'http://*.foo.bar/'
            }
        );
    }
);

# OpenID 1.1 compatibility check
$rp->discovery->protocol_version($Protocol::OpenID::Discovery::VERSION_1_1);
$sub->(
    $rp,
    sub {
        my ($self, $url, $result, $location, $params) = @_;

        is_deeply(
            $params,
            {   'openid.mode' => 'checkid_setup',
                'openid.identity'     => 'http://baz.foo.bar/',
                'openid.assoc_handle' => 'ABC',
                'openid.return_to'    => 'http://foo.bar/',
                'openid.trust_root'   => 'http://*.foo.bar/'
            }
        );
    }
);
