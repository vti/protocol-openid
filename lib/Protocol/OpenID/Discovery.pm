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

1;
