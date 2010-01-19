package Protocol::OpenID::RP;

use strict;
use warnings;

use Protocol::OpenID;
use Protocol::OpenID::Nonce;
use Protocol::OpenID::Identifier;
use Protocol::OpenID::Parameters;
use Protocol::OpenID::Discoverer;
use Protocol::OpenID::Authentication::Request;
use Protocol::OpenID::Authentication::Response;

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub store_cb { @_ > 1 ? $_[0]->{store_cb} = $_[1] : $_[0]->{store_cb} }

sub find_cb { @_ > 1 ? $_[0]->{store_cb} = $_[1] : $_[0]->{store_cb} }

sub remove_cb {
    @_ > 1 ? $_[0]->{remove_cb} = $_[1] : $_[0]->{remove_cb};
}

sub immediate_request {
    @_ > 1
      ? $_[0]->{immediate_request} = $_[1]
      : $_[0]->{immediate_request};
}

sub _return_to {
    @_ > 1 ? $_[0]->{_return_to} = $_[1] : $_[0]->{_return_to};
}

sub _realm { @_ > 1 ? $_[0]->{_realm} = $_[1] : $_[0]->{_realm} }

sub discoverer {
    @_ > 1 ? $_[0]->{discoverer} = $_[1] : $_[0]->{discoverer};
}

sub association {
    @_ > 1 ? $_[0]->{association} = $_[1] : $_[0]->{association};
}

sub _associate_counter {
    @_ > 1
      ? $_[0]->{_associate_counter} = $_[1]
      : $_[0]->{_associate_counter};
}

sub error { @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error} }

sub debug { $ENV{PROTOCOL_OPENID_DEBUG} || 0 }

sub new {
    my $class  = shift;
    my %params = @_;

    my $return_to = delete $params{return_to};

    my $self = {%params};
    bless $self, $class;

    $self->{find_cb}   ||= sub { };
    $self->{remove_cb} ||= sub { };
    $self->{immediate_request}  ||= 0;
    $self->{_associate_counter} ||= 0;

    $self->{discoverer} ||= Protocol::OpenID::Discoverer->new(
        http_req_cb => $self->http_req_cb);

    $self->return_to($return_to) if $return_to;

    return $self;
}

sub return_to {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new($value);

        $self->_return_to($identifier->to_string);

        return $self;
    }

    return $self->_return_to;
}

sub realm {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new($value);

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

    # From User Agent
    if (my $openid_identifier = $params->{'openid_identifier'}) {

        # Normalize
        my $identifier =
          Protocol::OpenID::Identifier->new($openid_identifier);

        # Discover
        $self->discoverer->discover(
            $identifier => sub {
                my ($discoverer, $discovery) = @_;

                # Discovery failed
                if (!$discovery) {
                    $self->error($discoverer->error);
                    return $cb->($self, 0);
                }

                use Data::Dumper;
                warn Dumper $discovery;

                $self->_associate(
                    $discovery->op_endpoint,
                    sub {
                        my ($self, $association) = @_;

                        # Store association
                        if (!$self->error && $association) {
                            warn 'Association ran fine, storing it'
                              if $self->debug;

                            my $assoc_handle =
                              $association->assoc_handle;

                            return $self->store_cb->(
                                $assoc_handle => $self->to_hash,
                                sub { return $self->_redirect($cb); }
                            );
                        }

                        # Skip association
                        elsif (!$self->error) {
                            warn 'Skipping association for various reasons'
                              if $self->debug;
                        }

                      # Give up on association, but don't fail, it is OPTIONAL
                        else {
                            warn 'Association failed: ' . $self->error
                              if $self->debug;
                        }

                        return $self->_redirect($discovery, undef, $cb);
                    }
                );
            }
        );
    }

    # From OP
    elsif (my $mode = $params->{'openid.mode'}) {
        #my $ns = $params->{'openid.ns'};
        #if (grep { $_ eq $mode } (qw/cancel error/)) {
        #    return $cb->($self, $openid_identifier, $mode);
        #}
        #elsif ($ns
        #    && $ns   eq $Protocol::OpenID::Discovery::VERSION_2_0
        #    && $mode eq 'setup_needed')
        #{
        #    return $cb->($self, $openid_identifier, $mode);
        #}
        #elsif ((!$ns || $ns ne $Protocol::OpenID::Discovery::VERSION_2_0)
        #    && $mode eq 'user_setup_url')
        #{
        #    return $cb->($self, $openid_identifier, $mode);
        #}
        #elsif ($mode eq 'id_res') {

        #    # Verify successful response
        #    return $self->_verify($params, $cb);
        #}
        #else {
        #    $self->error('Unknown mode');
        #    return $cb->($self, undef, 'error');
        #}
    }

    # Do nothing
    else {
        return $cb->($self, undef, 'null');
    }
}

sub clear {
    my $self = shift;

    $self->error('');
    $self->discovery(undef);
    $self->association(undef);

    return $self;
}

sub _associate {
    my $self = shift;
    my ($op_endpoint, $cb) = @_;

    # No point to send association unless we can store it
    return $cb->($self) unless $self->store_cb;

    my $request = Protocol::OpenID::Association::Request->new;

    $self->http_req_cb(
        $op_endpoint => 'POST' => {} => $request->to_hash => sub {
            my ($url, $status, $headers, $body) = @_;

            # Wrong status
            unless ($status && $status == 200) {
                $self->error('');
                return $cb->($self);
            }

            my $response = Protocol::OpenID::Association::Response->new;

            # Wrong body response
            unless ($response->parse($body)) {
                $self->error($response->error);
                return $cb->($self);
            }

            # Error response
            if ($response->error) {

                # TODO
            }

            # Successful response
            else {

                # Check the successful response itself
                unless ($request->assoc_type eq $response->assoc_type
                    && $request->session_type eq $response->session_type)
                {
                    $self->error('Association error');
                    return $cb->($self);
                }

                return $cb->($self, $response);
            }
        }
    );
}

sub _redirect {
    my $self = shift;
    my ($discovery, $assoc_handle, $cb) = @_;

    my $req = Protocol::OpenID::Authentication::Request->new;
    $req->ns($discovery->ns);
    $req->claimed_identifier($discovery->claimed_identifier);
    $req->return_to($self->return_to);

    $req->immediate_request(1) if $self->immediate_request;

    $req->assoc_handle($assoc_handle) if $assoc_handle;

    # Redirect to OP
    return $cb->(
        $self, $discovery->op_endpoint,
        'redirect',
        {location => $discovery->op_endpoint, params => $req->to_hash}
    );
}

sub _verify {
    my $self = shift;
    my ($params, $cb) = @_;

    # Check return_to
    return $cb->($self, undef, 'error')
      unless $self->_return_to_is_valid($params->{'openid.return_to'});

    # TODO: Check Discovered Information
    unless ($params->{'openid.identity'}) {
        $self->error('Wrong identity');
        return $cb->($self, undef, 'error');
    }

    my $ns = $params->{'openid.ns'}
      || $Protocol::OpenID::Discovery::VERSION_1_1;

    # Check nonce
    if ($ns eq $Protocol::OpenID::Discovery::VERSION_2_0) {
        return $cb->($self, undef, 'error')
          unless $self->_nonce_is_valid($params->{'openid.response_nonce'});
    }

    # Look if we have invalidate_handle field, and automatically delete that
    # association from the store
    return $self->_verify_handle(
        $params,
        sub {
            my ($self, $is_valid) = @_;

            # Proceed with direct authentication unless handle is valid
            return $self->_authenticate_directly($params, $cb)
              unless $is_valid;

            # Check assocition, look into the store
            return $self->_verify_association(
                $params,
                sub {
                    my ($self, $is_valid) = @_;

                    # Proceed with direct authentication unless correct
                    # association handle was found
                    return $self->_authenticate_directly($params, $cb)
                      unless $is_valid;

                    # User is verified
                    return $cb->($self, undef, 'verified');
                }
            );
        }
    );
}

sub _return_to_is_valid {
    my $self  = shift;
    my $param = shift;

    unless ($param && $self->return_to eq $param) {
        $self->error('Wrong return_to');

        return 0;
    }

    return 1;
}

sub _verify_handle {
    my $self = shift;
    my ($params, $cb) = @_;

    return $cb->($self, 0) unless $self->store_cb;

    if (my $handle = $params->{'openid.invalidate_handle'}) {
        warn "Removing handle '$handle'" if $self->debug;
        $self->remove_cb->($handle, sub { });
    }

    my $key = $params->{'openid.assoc_handle'};

    my $handle = $self->find_cb->($key);
    return $cb->($self, 0) unless $handle;
    warn "Handle '$handle' was found" if $self->debug;

    $self->association(Protocol::OpenID::Association->new(%$handle));

    return $cb->($self, 1);
}

sub _verify_association {
    my $self = shift;
    my ($params, $cb) = @_;

    my $association = $self->association;
    return $cb->($self, 0) unless $association;

    my $op_signature = $params->{'openid.sig'};

    my $sg = Protocol::OpenID::Signature->new(
        algorithm => $association->assoc_type,
        params    => $params
    );

    my $rp_signature = $sg->calculate($association->enc_mac_key);

    return $cb->($self, 0) unless $op_signature eq $rp_signature;

    warn 'Signatures match' if $self->debug;
    return $cb->($self, 1);
}

sub _authenticate_directly {
    my ($self, $params, $cb) = @_;

    my $op_endpoint;

    my $ns = $params->{'openid.ns'};

    if ($ns && $ns eq $Protocol::OpenID::Discovery::VERSION_2_0) {
        $op_endpoint = $params->{'openid.op_endpoint'};
    }

    # Forced to make a discovery again :(
    else {
        my $id =
          Protocol::OpenID::Identifier->new($params->{'openid.identity'});

        $self->clear_discovery;

        return $self->call(
            discover => [$self, $id] => sub {
                my ($ctl, $args, $is_done) = @_;

                # Return if discovery was unsuccessful
                return $cb->($self, undef, 'error')
                  unless $self->discovery;

                $op_endpoint = $self->discovery->op_endpoint;

                # Verifying Directly with the OpenID Provider
                return $self->_authenticate_directly_req($op_endpoint,
                    {params => $params}, $cb);
            }
        );
    }

    my $discovery = Protocol::OpenID::Discovery->new(
        claimed_identifier => $ns eq $Protocol::OpenID::Discovery::VERSION_2_0
        ? $params->{'openid.claimed_id'}
        : $params->{'openid.identity'}
    );
    $self->discovery($discovery);

    # Verifying Directly with the OpenID Provider
    return $self->_authenticate_directly_req($op_endpoint,
        {params => $params}, $cb);
}

sub _authenticate_directly_req {
    my ($self, $url, $args, $cb) = @_;

    warn 'Direct authentication' if $self->debug;

    # When using Direct Authentication we must take all the params we've got
    # from the OP (instead of the mode) and send them back
    my $params =
      {%{$args->{params}}, 'openid.mode' => 'check_authentication'};

    return $self->http_req_cb->(
        $self,
        $url => 'POST',
        {},
        $params,
        sub {
            my ($self, $op_endpoint, $args) = @_;

            my $status = $args->{status};
            my $body   = $args->{body};

            unless ($status && $status == 200) {
                $self->error(
                    'Wrong provider direct authentication response status');
                return $cb->($self, undef, 'error');
            }

            my $params = Protocol::OpenID::Parameters->new($body);
            unless ($params->param('is_valid')) {
                warn $body if $self->debug;
                $self->error('is_valid field is missing');
                return $cb->($self, undef, 'error');
            }

            if ($params->param('is_valid') eq 'true') {

                # Finally verified user
                return $cb->(
                    $self, $self->discovery->claimed_identifier, 'verified'
                );
            }

            $self->error('Not a valid user');

            if ($params->param('invalidate_handle')) {
                die 'SUPPORT ME!';
            }

            return $cb->($self, undef, 'error');
        }
    );
}

1;
