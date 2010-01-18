package Protocol::OpenID::Authentication::Request;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication';

use Protocol::OpenID;
use Protocol::OpenID::Identifier;

sub new {
    my $self = shift->SUPER::new(@_);

    $self->{ns} ||= OPENID_VERSION_2_0;

    $self->{claimed_identifier}  ||= OPENID_IDENTIFIER_SELECT;
    $self->{op_local_identifier} ||= OPENID_IDENTIFIER_SELECT;

    return $self;
}

sub immediate_request {
    @_ > 1 ? $_[0]->{immediate_request} = $_[1] : $_[0]->{immediate_request};
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

sub return_to {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new($value);

        $self->{return_to} = $identifier->to_string;

        return $self;
    }

    return $self->{return_to};
}

sub realm {
    my $self = shift;

    if (my $value = shift) {
        my $identifier = Protocol::OpenID::Identifier->new($value);

        $self->{realm} = $identifier->to_string;

        return $self;
    }

    return $self->{realm};
}

sub to_hash {
    my $self = shift;

    my $hash = {};

    # Prepare params
    $hash->{'openid.mode'} =
      $self->immediate_request
      ? 'checkid_immediate'
      : 'checkid_setup';

    $hash->{'openid.return_to'} = $self->return_to if $self->return_to;
    $hash->{'openid.assoc_handle'} = $self->assoc_handle
      if $self->assoc_handle;

    if ($self->ns eq OPENID_VERSION_2_0) {
        $hash->{'openid.ns'}         = $self->ns;
        $hash->{'openid.claimed_id'} = $self->claimed_identifier;

        if ($self->claimed_identifier ne
            'http://specs.openid.net/auth/2.0/identifier_select'
            && $self->op_local_identifier eq
            'http://specs.openid.net/auth/2.0/identifier_select')
        {
            $hash->{'openid.identity'} = $self->claimed_identifier;
        }
        else {
            $hash->{'openid.identity'} = $self->op_local_identifier;
        }

        $hash->{'openid.realm'} =
          $self->realm ? $self->realm : $self->return_to;
    }
    else {
        $hash->{'openid.identity'} = $self->op_local_identifier;

        $hash->{'openid.trust_root'} =
          $self->realm ? $self->realm : $self->return_to;
    }

    return $hash;
}

1;
