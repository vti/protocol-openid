package Protocol::OpenID::Discovery;

use strict;
use warnings;

our $VERSION_1_0 = 'http://openid.net/signon/1.0';
our $VERSION_1_1 = 'http://openid.net/signon/1.1';
our $VERSION_2_0 = 'http://specs.openid.net/auth/2.0';

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{protocol_version} ||= $VERSION_2_0;
    $self->{claimed_identifier}
      ||= 'http://specs.openid.net/auth/2.0/identifier_select';
    $self->{op_local_identifier}
      ||= 'http://specs.openid.net/auth/2.0/identifier_select';

    return $self;
}

sub op_identifier {
    @_ > 1 ? $_[0]->{op_identifier} = $_[1] : $_[0]->{op_identifier};
}

sub protocol_version {
    @_ > 1 ? $_[0]->{protocol_version} = $_[1] : $_[0]->{protocol_version};
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

sub clear {
    my $self = shift;


    return $self;
}

1;
