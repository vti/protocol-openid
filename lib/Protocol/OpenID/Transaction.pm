package Protocol::OpenID::Transaction;

use strict;
use warnings;

use Protocol::OpenID;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{state} = 'init';

    return $self;
}

sub identifier {
    @_ > 1 ? $_[0]->{identifier} = $_[1] : $_[0]->{identifier};
}

sub request {
    @_ > 1 ? $_[0]->{request} = $_[1] : $_[0]->{request};
}

sub response {
    @_ > 1 ? $_[0]->{response} = $_[1] : $_[0]->{response};
}

sub state_cb {
    @_ > 1 ? $_[0]->{state_cb} = $_[1] : $_[0]->{state_cb};
}

sub association {
    @_ > 1 ? $_[0]->{association} = $_[1] : $_[0]->{association};
}

sub error {
    @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error};
}

sub op_identifier {
    @_ > 1 ? $_[0]->{op_identifier} = $_[1] : $_[0]->{op_identifier};
}

sub ns {
    @_ > 1 ? $_[0]->{ns} = $_[1] : $_[0]->{ns};
}

sub op_endpoint {
    @_ > 1 ? $_[0]->{op_endpoint} = $_[1] : $_[0]->{op_endpoint};
}

sub state {
    my $self = shift;

    if (@_) {
        $self->{state} = shift;
        $self->state_cb->($self) if $self->state_cb;
    }
    else {
        return $self->{state};
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

sub to_hash {
    my $self = shift;

    my $hash = {};

    $hash->{ns} = $self->ns if $self->ns;

    if ($self->ns) {
        $hash->{claimed_identifier}  = $self->claimed_identifier;
        $hash->{op_local_identifier} = $self->op_local_identifier;
    }

    $hash->{op_identifier} = $self->op_identifier
      if $self->op_identifier;
    $hash->{op_endpoint} = $self->op_endpoint if $self->op_endpoint;

    $hash->{state} = $self->state;

    if ($self->association) {
        $hash->{association} = $self->association->to_hash;
    }

    return $hash;
}

sub from_hash {
    my $self = shift;
    my $hash = shift;

    foreach my $method (
        qw/
        ns
        claimed_identifier
        op_local_identifier
        op_identifier
        op_endpoint
        /
      )
    {
        $self->$method($hash->{$method}) if $hash->{$method};
    }
}

1;
