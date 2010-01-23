package Protocol::OpenID::RP;

use strict;
use warnings;

use Protocol::OpenID;
use Protocol::OpenID::Transaction;
use Protocol::OpenID::Identifier;
use Protocol::OpenID::Discoverer;
use Protocol::OpenID::Signature;
use Protocol::OpenID::Association::Request;
use Protocol::OpenID::Association::Response;
use Protocol::OpenID::Authentication::Request;
use Protocol::OpenID::Authentication::Response;
use Protocol::OpenID::Authentication::DirectRequest;
use Protocol::OpenID::Authentication::DirectResponse;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} ? 1 : 0;

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub store_cb { @_ > 1 ? $_[0]->{store_cb} = $_[1] : $_[0]->{store_cb} }

sub find_cb { @_ > 1 ? $_[0]->{store_cb} = $_[1] : $_[0]->{store_cb} }

sub remove_cb {
    @_ > 1 ? $_[0]->{remove_cb} = $_[1] : $_[0]->{remove_cb};
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

    $self->{find_cb}   ||= sub { };
    $self->{remove_cb} ||= sub { };

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

sub authenticate {
    my $self = shift;
    my ($params, $cb) = @_;

    # return_to is not required, but when omitted realm MUST be sent
    die 'realm is required when return_to is omitted'
      if !$self->return_to && !$self->realm;

    my $tx = Protocol::OpenID::Transaction->new;

    # 7.1. Initiation from User Agent
    if (my $openid_identifier = $params->{'openid_identifier'}) {

        # 7.2. Normalization
        my $identifier = Protocol::OpenID::Identifier->new;

        unless ($identifier->parse($openid_identifier)) {
            warn "$identifier";
            $tx->error('Wrong OpenID identifier');
            return $cb->($self, $tx);
        }

        $tx->identifier($identifier->to_string);

        # 7.3. Discovery
        return $self->_discover(
            $tx => sub {
                my ($self, $tx) = @_;

                # Discovery failed
                return $cb->($self, $tx) if $tx->error;

                # Association
                return $self->_associate(
                    $tx => sub {
                        my ($self, $tx) = @_;

                        my $req =
                          Protocol::OpenID::Authentication::Request->new;

                        $req->ns($tx->ns);
                        $req->claimed_identifier($tx->claimed_identifier);
                        $req->return_to($self->return_to);

                        # Association is OPTIONAL
                        $req->assoc_handle($tx->association->assoc_handle)
                          if $tx->association;

                        # Save transaction
                        #use Data::Dumper;
                        #warn Dumper $tx;
                        #$self->store_cb();

                        $tx->request($req);
                        $tx->state('redirect');

                        return $cb->($self, $tx);
                    }
                );
            }
        );
    }

    # Authentication response from OP
    elsif (my $mode = $params->{'openid.mode'}) {

        warn 'Authentication response from OP' if DEBUG;

        my $response = Protocol::OpenID::Authentication::Response->new;

        my $ok = $response->from_hash($params);
        unless ($ok) {
            $tx->error($response->error
                  || "Can't parse authentication response from OP");
            return $cb->($self, $tx);
        }

        $tx->response($response);

        unless ($response->mode eq 'id_res') {
            $tx->state($response->mode);
            return $cb->($self, $tx);
        }

        # 11. Verifying Assertions

      # The value of "openid.return_to" matches the URL of the current request
      # (Section 11.1 (Verifying the Return URL))
        if ($self->return_to ne $response->return_to) {
            $tx->error('Return to values do not match');
            return $cb->($self, $tx);
        }

        # Discovered information matches the information in the assertion
        # (Section 11.2 (Verifying Discovered Information))

       # An assertion has not yet been accepted from this OP with the same
       # value for "openid.response_nonce" (Section 11.3 (Checking the Nonce))

      # The signature on the assertion is valid and all fields that are
      # required to be signed are signed (Section 11.4 (Verifying Signatures))

        $self->_verify_signature(
            $tx => sub {
                my ($self, $tx) = @_;

                return $cb->($self, $tx) if $tx->error;

                $tx->state('success');
                return $cb->($self, $tx);
            }
        );
    }

    # Do nothing
    else {
        $tx->state('init');
        $cb->($self, $tx);
    }
}

sub _discover {
    my $self = shift;
    my ($tx, $cb) = @_;

    $tx->state('discovery');

    my $identifier = $tx->identifier;

    $self->cache_get_cb->(
        "discover:$identifier" => sub {
            my ($cache) = @_;

            if ($cache) {
                warn 'Discovery cache hit' if DEBUG;

                $tx->from_hash($cache);
                return $cb->($self, $tx);
            }

            Protocol::OpenID::Discoverer->discover(
                $self->http_req_cb => $tx => sub {
                    my ($tx) = @_;

                    if (!$tx->error) {
                        $self->cache_set_cb->(
                            "discover:$identifier",
                            $tx->to_hash => sub {
                                warn 'Cached discovery' if DEBUG;

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

    warn 'Performing association' if DEBUG;

    $tx->state('association');

    my $request = Protocol::OpenID::Association::Request->new;

    my $op_endpoint = $tx->op_endpoint;

    $self->http_req_cb->(
        $op_endpoint => 'POST' => {} => $request->to_hash => sub {
            my ($url, $status, $headers, $body) = @_;

            # Wrong status
            unless ($status && $status == 200) {
                warn 'Wrong return status during association' if DEBUG;
                return $cb->($self, $tx);
            }

            my $response = Protocol::OpenID::Association::Response->new;

            # Wrong body response
            unless ($response->parse($body)) {
                warn 'Wrong association response' if DEBUG;
                return $cb->($self, $tx);
            }

            # Error response
            if ($response->param('error')) {

                # TODO
            }

            # Successful response
            else {

                # Check the successful response itself
                unless ($request->assoc_type eq $response->assoc_type
                    && $request->session_type eq $response->session_type)
                {
                    warn 'Association error' if DEBUG;
                    return $cb->($self, $tx);
                }

                warn 'Association ran fine' if DEBUG;

                # Save association to the transaction
                $tx->association($response);

                $self->store_cb->(
                    $response->assoc_handle => $response->to_hash => sub {
                        return $cb->($self, $tx);
                    }
                );
            }
        }
    );
}

sub _verify_signature {
    my ($self, $tx, $cb) = @_;

    $self->find_cb->(
        $tx->response->assoc_handle => sub {
            my ($handle) = @_;

            if ($handle) {
                my $op_signature = $tx->response->sig;

                my $sg = Protocol::OpenID::Signature->new(
                    algorithm => $handle->{assoc_type},
                    params    => $tx->response->to_hash
                );

                my $rp_signature = $sg->calculate($handle->{enc_mac_key});

                if ($op_signature ne $rp_signature) {
                    $self->remove_cb->(
                        $handle =>
                          sub { $self->_verify_signature_directly($tx, $cb); }
                    );
                }
                else {
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

    my $direct_request =
      Protocol::OpenID::Authentication::DirectRequest->new($tx->response);

    $self->http_req_cb->(
        $tx->op_endpoint,
        'POST',
        {},
        $direct_request->to_hash => sub {
            my ($url, $status, $headers, $body) = @_;

            unless ($status && $status == 200) {
                $tx->error(
                    'Wrong provider direct authentication response status');
                return $cb->($self, $tx);
            }

            my $direct_response =
              Protocol::OpenID::Authentication::DirectResponse->new;

            if (!$direct_response->parse($body)) {
                $tx->error($direct_response->error);
                return $cb->($self, $tx);
            }

            $cb->($self, $tx);
        }
    );
}

1;
