package Protocol::OpenID::Discoverer;

use strict;
use warnings;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::OpenID::Discoverer::HTML;

# Yadis discovery requires Protocol::Yadis
use constant YADIS => eval { require Protocol::OpenID::Discoverer::Yadis; 1 };

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    return $self;
}

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub error {
    my $self = shift;

    if (@_) {
        $self->{error} = $_[0];
        warn "Error: " . ($self->{error} || 'Unknown') if DEBUG;
    }
    else {
        return $self->{error};
    }
}

sub discover {
    my $self = shift;
    my ($identifier, $cb) = @_;

    $self->error('');

    die 'Identifier is required' unless $identifier;

    $self->_yadis_discover(
        $identifier => sub {
            my ($discoverer, $discovery) = @_;

            return $cb->($self, $discovery) if $discovery;

            $self->error($discoverer->error);

            $self->_html_discover(
                $identifier => sub {
                    my ($discoverer, $discovery) = @_;

                    return $cb->($self, $discovery) if $discovery;

                    $self->error($discoverer->error);

                    return $cb->($self);
                }
            );
        }
    );
}

sub _yadis_discover {
    my $self = shift;
    my ($identifier, $cb) = @_;

    return $cb->($self) unless YADIS;

    my $yadis =
      Protocol::OpenID::Discoverer::Yadis->new(
        http_req_cb => $self->http_req_cb);

    $yadis->discover($identifier => sub { $cb->(@_); });
}

sub _html_discover {
    my $self = shift;
    my ($identifier, $cb) = @_;

    my $html =
      Protocol::OpenID::Discoverer::HTML->new(
        http_req_cb => $self->http_req_cb);

    $html->discover($identifier => sub { $cb->(@_); });
}

1;
