package Protocol::OpenID::Message::AuthenticationResponse;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication';

use Protocol::OpenID;
use Protocol::OpenID::Nonce;

sub return_to      { shift->param('return_to'      => @_) }
sub claimed_id     { shift->param('claimed_id'     => @_) }
sub identity       { shift->param('identity'       => @_) }
sub assoc_handle   { shift->param('assoc_handle'   => @_) }
sub signed         { shift->param('signed'         => @_) }
sub sig            { shift->param('sig'            => @_) }
sub response_nonce { shift->param('response_nonce' => @_) }
sub op_endpoint    { shift->param('op_endpoint'    => @_) }

# OpenID 1.1
sub user_setup_url { shift->param('user_setup_url' => @_) }

sub invalidate_handle {
    @_ > 1 ? $_[0]->{invalidate_handle} = $_[1] : $_[0]->{invalidate_handle};
}

sub from_hash {
    my $self = shift;

    my $ok = $self->SUPER::from_hash(@_);
    return unless $ok;

    if (!$self->mode) {
        $self->error('Mode is missing');
        return;
    }

    return 1 if grep { $_ eq $self->mode } (qw/cancel error/);

    return 1 if $self->ns && $self->mode eq 'setup_needed';

    if (!$self->ns && $self->param('user_setup_url')) {
        $self->mode('setup_needed');
        $self->user_setup_url($self->param('user_setup_url'));
        return 1;
    }

    # Validate successful response
    return 1 if $self->mode eq 'id_res' && $self->_validate;

    $self->error('Unknown mode') unless $self->error;
    return;
}

sub to_hash {
    my $self = shift;

    my $hash = $self->SUPER::to_hash();

    if (  !$hash->{'openid.ns'}
        && $hash->{'openid.mode'}
        && $hash->{'openid.mode'} eq 'setup_needed')
    {
        $hash->{'openid.mode'}           = 'id_res';
        $hash->{'openid.user_setup_url'} = $self->user_setup_url;
    }

    return $hash;
}

sub _validate {
    my $self = shift;

    # Check return_to
    unless ($self->return_to) {
        $self->error('Return to is missing');
        return;
    }

    # Check OP Endpoint URL
    if ($self->ns && !$self->op_endpoint) {
        $self->error('OP Endpoint is missing');
        return;
    }

    # Check nonce
    if ($self->ns) {
        if (!$self->response_nonce) {
            $self->error('Nonce is missing');
            return;
        }

        return unless $self->_is_valid_nonce;
    }

    # Check association handle
    unless ($self->assoc_handle) {
        $self->error('Association handle is missing');
        return;
    }

    # Check signed
    unless ($self->signed) {
        $self->error('Signed is missing');
        return;
    }

    # Check sig
    unless ($self->sig) {
        $self->error('Sig is missing');
        return;
    }

    return $self;
}

sub _is_valid_nonce {
    my $self = shift;

    my $nonce = Protocol::OpenID::Nonce->new;

    unless ($nonce->parse($self->response_nonce)) {
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
