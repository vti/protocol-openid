package Protocol::OpenID::Authentication::Response;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication';

use Protocol::OpenID;
use Protocol::OpenID::Nonce;

sub mode { @_ > 1 ? $_[0]->{mode} = $_[1] : $_[0]->{mode} }

sub return_to { @_ > 1 ? $_[0]->{return_to} = $_[1] : $_[0]->{return_to} }

sub claimed_id { @_ > 1 ? $_[0]->{claimed_id} = $_[1] : $_[0]->{claimed_id} }
sub identity { @_ > 1 ? $_[0]->{identity} = $_[1] : $_[0]->{identity} }

sub invalidate_handle {
    @_ > 1 ? $_[0]->{invalidate_handle} = $_[1] : $_[0]->{invalidate_handle};
}

sub signed { @_ > 1 ? $_[0]->{signed} = $_[1] : $_[0]->{signed} }
sub sig { @_ > 1 ? $_[0]->{sig} = $_[1] : $_[0]->{sig} }

sub response_nonce { @_ > 1 ? $_[0]->{response_nonce} = $_[1] : $_[0]->{response_nonce} }

sub op_endpoint { @_ > 1 ? $_[0]->{op_endpoint} = $_[1] :
    $_[0]->{op_endpoint} }

sub to_hash {
    my $self = shift;
    my $hash = {};

    for my $key (
        qw/
        ns
        mode
        return_to
        response_nonce
        claimed_id
        identity
        op_endpoint
        signed
        sig
        /
      )
    {
        $hash->{"openid.$key"} = $self->$key if $self->$key;
    }

    return $hash;
}

sub from_hash {
    my $self = shift;
    my $params = shift;

    my $mode = $params->{'openid.mode'};
    if (!$mode) {
        $self->error('Mode is missing');
        return;
    }

    my $ns = $params->{'openid.ns'} || OPENID_VERSION_1_1;
    $self->ns($ns);

    if (grep { $_ eq $mode } (qw/cancel error/)) {
        $self->mode($mode);
        return $self;
    }
    elsif ($ns   eq OPENID_VERSION_2_0
        && $mode eq 'setup_needed')
    {
        $self->mode($mode);
        return $self;
    }
    elsif (($ns ne OPENID_VERSION_2_0) && $mode eq 'user_setup_url')
    {
        $self->mode($mode);
        return $self;
    }
    elsif ($mode eq 'id_res') {
        $self->mode($mode);

        # Validate successful response
        if ($self->_validate($params)) {
            $self->return_to($params->{'openid.return_to'});

            $self->assoc_handle($params->{'openid.assoc_handle'})
              if $params->{'openid.assoc_handle'};

            $self->response_nonce($params->{'openid.response_nonce'});

            $self->op_endpoint($params->{'openid.op_endpoint'});

            $self->claimed_id($params->{'openid.claimed_id'})
              if $params->{'openid.claimed_id'};
            $self->identity($params->{'openid.identity'})
              if $params->{'openid.identity'};

            $self->invalidate_handle(1)
              if $params->{'openid.invalidate_handle'};

            $self->signed($params->{'openid.signed'})
              if $params->{'openid.signed'};

            $self->sig($params->{'openid.sig'})
              if $params->{'openid.sig'};
        }
        else {
            return;
        }
    }
    else {
        $self->error('Unknown mode');
        return;
    }

    return $self;
}

sub _validate {
    my $self = shift;
    my $params = shift;

    # Check return_to
    unless ($params->{'openid.return_to'}) {
        $self->error('Return to is missing');
        return;
    }

    # Check OP Endpoint URL
    unless ($params->{'openid.op_endpoint'}) {
        $self->error('OP Endpoint is missing');
        return;
    }

    # Check nonce
    if ($self->ns eq OPENID_VERSION_2_0) {
        if (!$params->{'openid.response_nonce'}) {
            $self->error('Nonce is missing');
            return;
        }

        return
          unless $self->_is_valid_nonce($params->{'openid.response_nonce'});
    }

    # Check signed
    unless ($params->{'openid.signed'}) {
        $self->error('Signed is missing');
        return;
    }

    # Check sig
    unless ($params->{'openid.sig'}) {
        $self->error('Sig is missing');
        return;
    }

    return $self;
}

sub _is_valid_nonce {
    my $self  = shift;
    my $param = shift;

    my $nonce = Protocol::OpenID::Nonce->new;

    unless ($nonce->parse($param)) {
        $self->error('Wrong nonce');
        return 0;
    }

    my $epoch = $nonce->epoch;
    my $time  = time;

    # Check if nonce isn't too far in the future (2 hours)
    if ($epoch < $time - 3600 * 2) {
        $self->error('Nonce is too old');
        return 0;
    }

    # Check if nonce isn't too old (2 hours)
    if ($epoch > $time + 3600 * 2) {
        $self->error('Nonce is in the future');
        return 0;
    }

    return 1;
}

1;
