package Protocol::OpenID::Discoverer;

use strict;
use warnings;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Async::Hooks;
use Protocol::OpenID::Discoverer::Yadis;
use Protocol::OpenID::Discoverer::HTML;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    my @discoverers = (

        # Yadis discovery hook
        Protocol::OpenID::Discoverer::Yadis->new(
            http_req_cb => $self->http_req_cb
        ),

        # HTML discovery hook
        Protocol::OpenID::Discoverer::HTML->new(
            http_req_cb => $self->http_req_cb
        )
    );

    foreach my $discoverer (@discoverers) {
        $self->hook(
            discover => sub {
                my ($ctl, $args) = @_;
                $discoverer->discover(
                    @$args => sub {
                        my ($discoverer, $discovery) = @_;

                        unless ($discovery) {
                            $self->error($discoverer->error);
                            $ctl->next;
                            return;
                        }

                        $self->discovery($discovery);
                        $ctl->done;
                    }
                );
            }
        );
    }

    return $self;
}

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub hooks { $_[0]->{hooks} ||= Async::Hooks->new }
sub hook  { shift->hooks->hook(@_) }
sub call  { shift->hooks->call(@_) }

sub discovery {
    @_ > 1 ? $_[0]->{discovery} = $_[1] : $_[0]->{discovery};
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

    $self->call(
        discover => [$identifier] => sub {
            my ($ctl, $args, $is_done) = @_;

            unless ($is_done) {
                $self->error('Discovery failed');
            }

            $cb->($self, $self->discovery);
        }
    );
}

1;
