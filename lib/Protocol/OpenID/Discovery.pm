package Protocol::OpenID::Discovery;

use strict;
use warnings;

use Protocol::OpenID;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{ns} ||= OPENID_VERSION_2_0;

    $self->{claimed_identifier}  ||= OPENID_IDENTIFIER_SELECT;
    $self->{op_local_identifier} ||= OPENID_IDENTIFIER_SELECT;

    return $self;
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

sub to_hash {
    my $self = shift;

    my $hash = {};

    $hash->{ns}                  = $self->ns if $self->ns;
    $hash->{claimed_identifier}  = $self->claimed_identifier;
    $hash->{op_local_identifier} = $self->op_local_identifier;
    $hash->{op_identifier}       = $self->op_identifier
      if $self->op_identifier;
    $hash->{op_endpoint} = $self->op_endpoint if $self->op_endpoint;

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
