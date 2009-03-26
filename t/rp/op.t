use Test::More tests => 15;

use_ok('Protocol::OpenID::RP');

use Protocol::OpenID::Nonce;

my $rp = Protocol::OpenID::RP->new(
    return_to => 'http://foo.bar',
    http_req_cb => sub {
        my ($self, $url, $args, $cb) = @_;

        my $status = 200;
        my $res_headers = {};
        my $body;

        if ($url eq 'http://myserverprovider.com/') {
            my $nonce = Protocol::OpenID::Nonce->new;
            $body =<<"";
is_valid:true

        }

        $cb->($self => $url =>
              {status => $status, headers => $res_headers, body => $body});
    }
);

$rp->authenticate(
    {'openid.mode' => 'setup_needed'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'setup_needed');
    }
);
$rp->clear;

$rp->authenticate(
    {'openid.mode' => 'cancel'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'cancel');
    }
);
$rp->clear;

$rp->authenticate(
    {'openid.mode' => 'cancel'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'cancel');
    }
);
$rp->clear;

$rp->authenticate(
    {'openid.mode' => 'id_res'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'error');
        is($self->error, 'Wrong return_to');
    }
);
$rp->clear;

$rp->authenticate(
    {'openid.mode' => 'id_res', 'openid.return_to' => 'http://foo.ba'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action,      'error');
        is($self->error, 'Wrong return_to');
    }
);
$rp->clear;

$rp->authenticate(
    {'openid.mode' => 'id_res', 'openid.return_to' => 'http://foo.bar'},
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action,      'error');
        is($self->error, 'Wrong nonce');
    }
);
$rp->clear;

$rp->authenticate(
    {   'openid.mode'      => 'id_res',
        'openid.return_to' => 'http://foo.bar',
        'openid.responce_nonce'     => '2000-12-12T12:12:12ZHELLO'
    },
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action,      'error');
        is($self->error, 'Nonce is too old');
    }
);
$rp->clear;

$rp->authenticate(
    {   'openid.mode'      => 'id_res',
        'openid.return_to' => 'http://foo.bar',
        'openid.responce_nonce'     => '2029-12-12T12:12:12ZHELLO'
    },
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action,      'error');
        is($self->error, 'Nonce is in the future');
    }
);
$rp->clear;

$rp->authenticate(
    {   'openid.mode'        => 'id_res',
        'openid.return_to'   => 'http://foo.bar',
        'openid.responce_nonce'       => Protocol::OpenID::Nonce->new,
        'openid.op_endpoint' => 'http://myserverprovider.com/',
        'openid.claimed_id'  => 'http://user.myserverprovider.com/',
        'openid.identity'    => 'http://user.myserverprovider.com/',
        'openid.signed'      => 'foo',
        'openid.sig'         => 'bar'
    },
    sub {
        my ($self, $url, $action, $location) = @_;

        is($action, 'verified');
    }
);
$rp->clear;
