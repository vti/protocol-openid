package Protocol::OpenID::Revelation;

use strict;
use warnings;

use base 'Mojo::Base';

use Mojo::Client;
use Mojo::Transaction;

use Protocol::OpenID::Revelation::Yadis;
use Protocol::OpenID::Revelation::HTML;

__PACKAGE__->attr(identity => (chained => 1));

__PACKAGE__->attr(
    yadis => (
        chained => 1,
        default => sub { Protocol::OpenID::Discovery::Yadis->new }
    )
);
__PACKAGE__->attr(
    html => (
        chained => 1,
        default => sub { Protocol::OpenID::Discovery::HTML->new }
    )
);

sub reveal {
    my $self = shift;
    my $tx = shift;

    if ($tx->req->headers->header('Accept') eq 'application/xrds+xml') {
        my $document = Protocol::OpenID::Yadis::Document->new;

        my $service = Protocol::OpenID::Yadis::Document::Service->new;
        $service->type('http://specs.openid.net/auth/2.0/signon');
        $service->uri('http://127.0.0.1:4000/server');

        push @{$document->services}, $service;

        $tx->res->headers->header('Content-Type' => 'application/xrds+xml');

        $tx->res->code(200);
        $tx->res->body("$document");
    } else {
        $tx->res->headers->header('X-XRDS-Location' => '');
    }

    return $di;
}

1;
