package Protocol::OpenID::RP;
use Mouse;

use Async::Hooks;
use Protocol::Yadis;
use Protocol::OpenID::Nonce;
use Protocol::OpenID::Identifier;
use Protocol::OpenID::Parameters;
use Protocol::OpenID::Discovery;
use Protocol::OpenID::Discovery::Yadis;
use Protocol::OpenID::Discovery::HTML;

has hooks => (
    isa     => 'Async::Hooks',
    default => sub { Async::Hooks->new },
    is      => 'ro',
    lazy    => 1,
    handles => [qw( hook call )],
);

has http_req_cb => (
    isa      => 'CodeRef',
    is       => 'rw',
    required => 1
);

has return_to => (
    isa      => 'Str',
    is       => 'rw',
    required => 1
);

has store => (
    isa     => 'Protocol::OpenID::Store',
    is      => 'rw'
);

has discovery => (
    isa     => 'Protocol::OpenID::Discovery',
    is      => 'rw',
    clearer => 'clear_discovery'
);

has error => (
    isa => 'Str',
    is  => 'rw',
    clearer => 'clear_error'
);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new(@_);

    # Yadis discovery hook
    $self->hook(discover => \&Protocol::OpenID::Discovery::Yadis::hook);

    # HTML discovery hook
    $self->hook(discover => \&Protocol::OpenID::Discovery::HTML::hook);

    return $self;
}

sub authenticate {
    my $self = shift;
    my ($params, $cb) = @_;

    # From User Agent
    if (my $openid_identifier = $params->{'openid_identifier'}) {

        # Normalization
        my $identifier = Protocol::OpenID::Identifier->new($openid_identifier);

        # Discovery hook chain
        $self->call(
            discover => [$self, $identifier] => sub {
                my ($ctl, $args, $is_done) = @_;

                my $discovery = $self->discovery;

                # Return if discovery was unsuccessful
                return $cb->($self, undef, 'error') unless $discovery;

                # Prepare params
                my $params = Protocol::OpenID::Parameters->new(
                    ns         => 'http://specs.openid.net/auth/2.0',
                    mode       => 'checkid_setup',
                    claimed_id => $discovery->claimed_identifier,
                    identity   => $discovery->op_local_identifier,

                    #assoc_handle => $self->assoc_handle,
                    return_to    => $self->return_to,
                    #realm        => $self->realm
                );

                # Prepare url for redirection
                my $op_endpoint =
                  $discovery->op_endpoint . '?' . $params->to_query;

                # Redirect to OP
                $cb->($self, $openid_identifier, 'redirect', $op_endpoint);
            }
        );
    }

    # From OP
    elsif (my $mode = $params->{'openid.mode'}) {
        if (grep { $_ eq $mode } (qw/setup_needed cancel error/)) {
            $cb->($self, $openid_identifier, $mode);
        }
        elsif ($mode eq 'id_res') {

            # Check return_to
            unless ($params->{'openid.return_to'}
                && $self->return_to eq $params->{'openid.return_to'})
            {
                $self->error('Wrong return_to');

                return $cb->($self, undef, 'error');
            }

            # Check nonce
            my $nonce = Protocol::OpenID::Nonce->new;

            unless ($params->{'openid.response_nonce'}
                && $nonce->parse($params->{'openid.response_nonce'}))
            {
                $self->error('Wrong nonce');
                return $cb->($self, undef, 'error');
            }

            my $epoch = $nonce->epoch;
            my $time  = time;

            # Check if nonce isn't too far in the future (2 hours)
            if ($epoch < $time - 3600 * 2) {
                $self->error('Nonce is too old');
                return $cb->($self, undef, 'error');
            }

            # Check if nonce isn't too old (2 hours)
            if ($epoch > $time + 3600 * 2) {
                $self->error('Nonce is in the future');
                return $cb->($self, undef, 'error');
            }

            # Verify association
            if ($self->store) {
                die 'implement!';
            }

            # Verifying Directly with the OpenID Provider
            else {
                $self->http_req_cb->(
                    $self,
                    $params->{'openid.op_endpoint'} => {
                        method => 'POST',
                        params =>
                          {%$params, 'openid.mode' => 'check_authentication'}
                    },
                    sub {
                        my ($self, $url, $args) = @_;

                        my $status = $args->{status};
                        my $body   = $args->{body};

                        return $cb->($self, undef, 'error')
                          unless $status == 200;

                        my $params = Protocol::OpenID::Parameters->new($body);
                        unless ($params->param('is_valid')) {
                            $self->error('is_valid field is missing');
                            return $cb->($self, undef, 'error');
                        }

                        unless ($params->param('is_valid') eq 'true') {
                            $self->error('Not a valid user');
                            return $cb->($self, undef, 'error');
                        }

                        if ($params->param('invalidate_handle')) {
                            die 'SUPPORT ME!';
                        }

                        # Finally verified user
                        return $cb->($self, undef, 'verified');
                    }
                );
            }
        }
        else {
            $self->error('Unknown mode');
            $cb->($self, undef, 'error');
        }
    }
    # Do nothing
    else {
        $cb->($self, undef, 'null');
    }
}

sub clear {
    my $self = shift;

    $self->clear_error;
    $self->clear_discovery;
}

1;
