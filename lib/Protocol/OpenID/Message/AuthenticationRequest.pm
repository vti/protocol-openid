package Protocol::OpenID::Message::AuthenticationRequest;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

use Protocol::OpenID;
use Protocol::OpenID::Extension;

sub build {
    my $self = shift;

    $self->mode(
        $self->immediate_request ? 'checkid_immediate' : 'checkid_setup');

    if ($self->ns) {
        $self->claimed_id($self->claimed_identifier);

        if (   $self->claimed_id ne OPENID_IDENTIFIER_SELECT
            && $self->op_local_identifier eq OPENID_IDENTIFIER_SELECT)
        {
            $self->identity($self->claimed_id);
        }
        else {
            $self->identity($self->op_local_identifier);
        }

        $self->realm($self->realm ? $self->realm : $self->return_to);
    }
    else {
        $self->identity($self->op_local_identifier);

        $self->trust_root($self->realm ? $self->realm : $self->return_to);
    }
}

sub claimed_identifier {
    my ($self, $value) = @_;

    if (@_ > 1) {
        $self->{claimed_identifier} = $value;
    }
    elsif ($self->ns) {
        $self->{claimed_identifier} ||= OPENID_IDENTIFIER_SELECT;
    }

    return $self->{claimed_identifier};
}

sub op_local_identifier {
    my ($self, $value) = @_;

    if (@_ > 1) {
        $self->{op_local_identifier} = $value;
    }

    # OpenID 2.0
    elsif ($self->ns) {
        $self->{op_local_identifier} ||= OPENID_IDENTIFIER_SELECT;
    }

    # OpenID 1.1
    else {
        $self->{op_local_identifier} ||= $self->claimed_identifier;
    }

    return $self->{op_local_identifier};
}

sub return_to    { shift->param('return_to'    => @_) }
sub realm        { shift->param('realm'        => @_) }
sub assoc_handle { shift->param('assoc_handle' => @_) }
sub claimed_id   { shift->param('claimed_id'   => @_) }
sub identity     { shift->param('identity'     => @_) }

sub trust_root { shift->param('trust_root' => @_) }

sub immediate_request {
    @_ > 1 ? $_[0]->{immediate_request} = $_[1] : $_[0]->{immediate_request};
}

sub to_hash {
    my $self = shift;

    my $hash = $self->SUPER::to_hash;

    # OpenID 1.1
    unless ($self->ns) {
        delete $hash->{'openid.realm'};
    }

    return $hash;
}

1;
