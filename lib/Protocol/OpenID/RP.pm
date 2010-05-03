package Protocol::OpenID::RP;

use strict;
use warnings;

use Protocol::OpenID;
use Protocol::OpenID::Discoverer;
use Protocol::OpenID::Association;
use Protocol::OpenID::Transaction;

use Protocol::OpenID::Identifier;
use Protocol::OpenID::Signature;

use Protocol::OpenID::Message::AssociationRequest;
use Protocol::OpenID::Message::AssociationResponse;
use Protocol::OpenID::Message::AuthenticationRequest;
use Protocol::OpenID::Message::AuthenticationResponse;
use Protocol::OpenID::Message::VerificationRequest;
use Protocol::OpenID::Message::VerificationResponse;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} ? 1 : 0;

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub state_cb { @_ > 1 ? $_[0]->{state_cb} = $_[1] : $_[0]->{state_cb} }

sub store_cb { @_ > 1 ? $_[0]->{store_cb} = $_[1] : $_[0]->{store_cb} }

sub find_cb { @_ > 1 ? $_[0]->{find_cb} = $_[1] : $_[0]->{find_cb} }

sub remove_cb {
    @_ > 1 ? $_[0]->{remove_cb} = $_[1] : $_[0]->{remove_cb};
}

sub normal_cb {
    @_ > 1 ? $_[0]->{normal_cb} = $_[1] : $_[0]->{normal_cb};
}
sub redirect_cb {
    @_ > 1 ? $_[0]->{redirect_cb} = $_[1] : $_[0]->{redirect_cb};
}

sub canceled_cb {
    @_ > 1 ? $_[0]->{canceled_cb} = $_[1] : $_[0]->{canceled_cb};
}

sub setup_needed_cb {
    @_ > 1 ? $_[0]->{setup_needed_cb} = $_[1] : $_[0]->{setup_needed_cb};
}

sub error_cb {
    @_ > 1 ? $_[0]->{error_cb} = $_[1] : $_[0]->{error_cb};
}

sub success_cb {
    @_ > 1 ? $_[0]->{success_cb} = $_[1] : $_[0]->{success_cb};
}

sub _return_to {
    @_ > 1 ? $_[0]->{_return_to} = $_[1] : $_[0]->{_return_to};
}

sub _realm { @_ > 1 ? $_[0]->{_realm} = $_[1] : $_[0]->{_realm} }

sub cache_get_cb {
    @_ > 1 ? $_[0]->{cache_get_cb} = $_[1] : $_[0]->{cache_get_cb};
}

sub cache_set_cb {
    @_ > 1 ? $_[0]->{cache_set_cb} = $_[1] : $_[0]->{cache_set_cb};
}

our $CACHE = {};
my $CACHE_LIMIT = 100;
my $CACHE_TIME  = 60 * 30;

sub _cache_get_cb {
    my ($key, $cb) = @_;

    my $value = $CACHE->{$key};
    unless ($value) {
        warn "Cache miss: '$key'" if DEBUG;
        return $cb->();
    }

    # 30 minutes cache
    if (time - $value->{time} > $CACHE_TIME) {
        return $cb->();
    }

    return $cb->($value);
}

sub _cache_set_cb {
    my ($key, $value, $cb) = @_;

    if (keys %$CACHE > $CACHE_LIMIT) {
        warn 'Cleaning cache' if DEBUG;
        my @values =
          sort { $b->{time} <=> $a->{time} } values %$CACHE;

        $#values = $CACHE_LIMIT - 2;
        $CACHE   = {@values};
    }

    $CACHE->{$key} = {time => time, %{$value}};

    return $cb->();
}

sub new {
    my $class  = shift;
    my %params = @_;

    my $return_to = delete $params{return_to};

    my $self = {%params};
    bless $self, $class;

    $self->{cache_get_cb} ||= \&_cache_get_cb;
    $self->{cache_set_cb} ||= \&_cache_set_cb;

    my $a = $self->{find_cb};
    my $b = $self->{store_cb};
    unless (($a && $b) || (!$a && !$b)) {
        die 'find_cb and store_cb must be both undefined or defined';
    }

    $self->{extensions} = {};

    $self->return_to($return_to) if $return_to;

    return $self;
}

sub return_to {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new;
        $identifier->parse($value);

        $self->_return_to($identifier->to_string);

        return $self;
    }

    return $self->_return_to;
}

sub realm {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new;
        $identifier->parse($value);

        $self->_realm($identifier->to_string);

        return $self;
    }

    return $self->_realm;
}

sub extension {
    my $self = shift;
    my ($name, $ext) = @_;

    $self->{extensions}->{$name} = $ext;
}

sub authenticate {
    my $self = shift;
    my ($params, $cb) = @_;

    # return_to is not required, but when omitted realm MUST be sent
    die 'realm is required when return_to is omitted'
      if !$self->return_to && !$self->realm;

    my $tx = Protocol::OpenID::Transaction->new;

    $tx->state_cb(sub { $self->state_cb->(shift) }) if $self->state_cb;

    # 7.1. Initiation from User Agent
    if (my $openid_identifier = $params->{'openid_identifier'}) {

        # 7.2. Normalization
        my $identifier = Protocol::OpenID::Identifier->new;

        unless ($identifier->parse($openid_identifier)) {
            $tx->error('Wrong OpenID identifier');

            return $cb->($self, $tx) if $cb;
            return $self->error_cb->($tx);
        }

        $tx->identifier($identifier->to_string);
        $tx->state('identifier');

        # 7.3. Discovery
        return $self->_discover(
            $tx => sub {
                my ($self, $tx) = @_;

                # Discovery failed
                if ($tx->error) {
                    return $cb->($self, $tx) if $cb;
                    return $self->error_cb->($tx);
                }

                # Association
                return $self->_associate(
                    $tx => sub {
                        my ($self, $tx) = @_;

                        if ($tx->error) {
                            return $cb->($self, $tx) if $cb;
                            return $self->error_cb->($tx);
                        }

                        my $req =
                          Protocol::OpenID::Message::AuthenticationRequest->new;

                        $req->ns($tx->ns) if $tx->ns;
                        $req->claimed_identifier($tx->claimed_identifier);

                        $req->return_to($self->return_to);

                        # Extensions
                        foreach my $name (keys %{$self->{extensions}}) {
                            $req->extension(
                                $name => $self->{extensions}->{$name});
                        }

                        # Association is OPTIONAL
                        $req->assoc_handle($tx->association->assoc_handle)
                          if $tx->association;

                        $tx->request($req);
                        $tx->state('redirect');

                        return $cb->($self, $tx) if $cb;
                        return $self->redirect_cb->($tx);
                    }
                );
            }
        );
    }

    # Authentication response from OP
    elsif (my $mode = $params->{'openid.mode'}) {

        warn 'Authentication response from OP' if DEBUG;

        my $response = Protocol::OpenID::Message::AuthenticationResponse->new;

        my $ok = $response->from_hash($params);
        unless ($ok) {
            $tx->error($response->error
                  || "Can't parse authentication response from OP");
            return $cb->($self, $tx) if $cb;
            return $self->error_cb->($tx);
        }

        warn 'Save association to the OpenID transaction' if DEBUG;
        $tx->response($response);
        $tx->state('authentication_start');

        # Special case, error mode
        if ($response->mode eq 'error') {
            warn 'Authentication has an error' if DEBUG;
            $tx->error($response->param('error'));
            return $cb->($self, $tx) if $cb;
            return $self->error_cb->($tx);
        }

        unless ($response->mode eq 'id_res') {
            warn 'Authentication response is not successful' if DEBUG;
            $tx->state($response->mode);
            return $cb->($self, $tx) if $cb;

            if ($response->mode eq 'setup_needed') {
                my $location;

                # OpenID 1.1 sends url for user redirection
                $location = $response->user_setup_url unless $response->ns;

                return $self->setup_needed_cb->($tx, $location);
            }
            elsif ($response->mode eq 'cancel') {
                return $self->canceled_cb->($tx);
            }

            $self->error('Internal error');
            return;
        }

        $tx->identifier($response->identity);
        $tx->op_endpoint($response->op_endpoint);

        warn 'Verifying assertion' if DEBUG;

        $tx->state('verification_start');

        # 11. Verifying Assertions

      # The value of "openid.return_to" matches the URL of the current request
      # (Section 11.1 (Verifying the Return URL))
        if ($self->return_to ne $response->return_to) {
            $tx->error('Return to values do not match');
            return $cb->($self, $tx) if $cb;
            return $self->error_cb->($tx);
        }

        # Discovered information matches the information in the assertion
        # (Section 11.2 (Verifying Discovered Information))

       # An assertion has not yet been accepted from this OP with the same
       # value for "openid.response_nonce" (Section 11.3 (Checking the Nonce))

      # The signature on the assertion is valid and all fields that are
      # required to be signed are signed (Section 11.4 (Verifying Signatures))

      warn 'Verifying signature' if DEBUG;
        $self->_verify_signature(
            $tx => sub {
                my ($self, $tx) = @_;

                if ($tx->error) {
                    return $cb->($self, $tx) if $cb;
                    return $self->error_cb->($tx);
                }

                warn 'Signature is ok' if DEBUG;
                $tx->state('success');
                return $cb->($self, $tx) if $cb;
                return $self->success_cb->($tx);
            }
        );
    }

    # Do nothing
    else {
        warn 'Normal request' if DEBUG;
        $tx->state('init');
        return $cb->($self, $tx) if $cb;
        return $self->normal_cb->();
    }
}

sub _discover {
    my $self = shift;
    my ($tx, $cb) = @_;

    $tx->state('discovery_start');

    my $identifier = $tx->identifier;

    $self->cache_get_cb->(
        "discover:$identifier" => sub {
            my ($cache) = @_;

            if ($cache) {
                warn 'Discovery cache hit' if DEBUG;

                $tx->from_hash($cache);
                $tx->state('discovery_done');

                return $cb->($self, $tx);
            }

            warn 'No cache hit, doing real discovery' if DEBUG;
            Protocol::OpenID::Discoverer->discover(
                $self->http_req_cb => $tx => sub {
                    my ($tx) = @_;

                    if (!$tx->error) {
                        $self->cache_set_cb->(
                            "discover:$identifier",
                            $tx->to_hash => sub {
                                warn 'Cached discovery' if DEBUG;

                                $tx->state('discovery_done');

                                return $cb->($self, $tx);
                            }
                        );
                    }
                    else {
                        return $cb->($self, $tx);
                    }
                }
            );
        }
    );
}

sub _associate {
    my $self = shift;
    my ($tx, $cb) = @_;

    # No point to send association unless we can store it
    return $cb->($self, $tx) unless $self->store_cb;

    my $assoc = Protocol::OpenID::Association->new;

    warn 'Performing association' if DEBUG;

    $tx->state('association_start');

    my $request = Protocol::OpenID::Message::AssociationRequest->new($assoc);

    my $op_endpoint = $tx->op_endpoint;

    $self->http_req_cb->(
        $op_endpoint => 'POST' => {} => $request->to_hash => sub {
            my ($url, $status, $headers, $body, $error) = @_;

            if ($error) {
                return $cb->($self, $tx);
            }

            # Wrong status
            unless ($status && $status == 200) {
                warn 'Wrong return status during association' if DEBUG;
                return $cb->($self, $tx);
            }

            my $response =
              Protocol::OpenID::Message::AssociationResponse->new($assoc);

            # Wrong body response
            unless ($response->parse($body)) {
                warn 'Wrong association response' if DEBUG;
                return $cb->($self, $tx);
            }

            # Error response
            if ($assoc->error) {

                # TODO
            }

            # Successful response
            else {

                warn 'Association ran fine' if DEBUG;

                # Save association to the transaction
                $tx->association($assoc);
                $tx->state('association_done');

                $self->store_cb->($assoc->assoc_handle => $assoc->to_hash =>
                      sub { return $cb->($self, $tx); });
            }
        }
    );
}

sub _verify_signature {
    my ($self, $tx, $cb) = @_;

    $tx->state('verification_signature_start');
    return $self->_verify_signature_directly($tx, $cb) unless $self->find_cb;

    warn 'Try to find associaction in cache' if DEBUG;

    $self->find_cb->(
        $tx->response->assoc_handle => sub {
            if (my $assoc = shift) {

                my $op_signature = $tx->response->sig;

                my $sg =
                  Protocol::OpenID::Signature->new($tx->response->to_hash,
                    algorithm => $assoc->{assoc_type});

                my $rp_signature = $sg->calculate($assoc->{secret});

                if ($op_signature ne $rp_signature) {
                    warn 'Saved signature does not match' if DEBUG;
                    $self->remove_cb->(
                        $assoc->assoc_handle =>
                          sub { $self->_verify_signature_directly($tx, $cb); }
                    );
                }
                else {
                    $tx->state('verification_locally_done');
                    $cb->($self, $tx);
                }
            }
            else {
                $self->_verify_signature_directly($tx, $cb);
            }
        }
    );
}

sub _verify_signature_directly {
    my ($self, $tx, $cb) = @_;

    warn 'Verifying signature directly' if DEBUG;

    $tx->state('verification_directly_start');

    my $direct_request =
      Protocol::OpenID::Message::VerificationRequest->new($tx->response);

    # OpenID 1.1 compatibility
    if (!$tx->ns && !$tx->op_endpoint) {
        $self->_discover(
            $tx => sub {
                my ($self, $tx) = @_;

                # Discovery failed
                if ($tx->error) {
                    return $cb->($self, $tx) if $cb;
                    return $self->error_cb->($tx);
                }

                return $self->_verify_signature_directly_req($tx, $direct_request, $cb);
            }
        );
    }
    else {
        $self->_verify_signature_directly_req($tx, $direct_request, $cb);
    }

}

sub _verify_signature_directly_req {
    my ($self, $tx, $direct_request, $cb) = @_;

    $self->http_req_cb->(
        $tx->op_endpoint,
        'POST',
        {},
        $direct_request->to_hash => sub {
            my ($url, $status, $headers, $body, $error) = @_;

            if ($error) {
                $tx->error($error);
                return $cb->($self, $tx);
            }

            unless ($status && $status == 200) {
                $tx->error(
                    'Wrong provider direct authentication response status');
                return $cb->($self, $tx);
            }

            my $direct_response =
              Protocol::OpenID::Message::VerificationResponse->new;

            if (!$direct_response->parse($body)) {
                $tx->error($direct_response->error);
                return $cb->($self, $tx);
            }

            $tx->error('Signature not verified')
              if $direct_response->is_valid eq 'false';

            $tx->start('verification_directly_done');

            $cb->($self, $tx);
        }
    );
}

1;
