package Protocol::OpenID::Authentication::Request;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication';

use Protocol::OpenID;

sub new {
    my $class = shift;
    my %params = @_;

    my $claimed_identifier = delete $params{claimed_identifier}
      || OPENID_IDENTIFIER_SELECT;
    my $op_local_identifier = delete $params{op_local_identifier}
      || OPENID_IDENTIFIER_SELECT;

    my $self = $class->SUPER::new(%params);

    $self->claimed_identifier($claimed_identifier);
    $self->op_local_identifier($op_local_identifier);

    return $self;
}

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
    @_ > 1
      ? $_[0]->{claimed_identifier} = $_[1]
      : $_[0]->{claimed_identifier};
}

sub op_local_identifier {
    @_ > 1
      ? $_[0]->{op_local_identifier} = $_[1]
      : $_[0]->{op_local_identifier};
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

    unless ($self->ns) {
        delete $hash->{'openid.realm'};
    }

    return $hash;
}

1;
