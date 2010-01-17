package Protocol::OpenID::Association;

use strict;
use warnings;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{session_type} ||= '';
    $self->{assoc_type} ||= '';

    return $self;
}

sub assoc_handle {
    @_ > 1 ? $_[0]->{assoc_handle} = $_[1] : $_[0]->{assoc_handle};
}

sub assoc_type {
    @_ > 1 ? $_[0]->{assoc_type} = $_[1] : $_[0]->{assoc_type};
}

sub session_type {
    @_ > 1 ? $_[0]->{session_type} = $_[1] : $_[0]->{session_type};
}

sub dh_server_public {
    @_ > 1
      ? $_[0]->{dh_server_public} = $_[1]
      : $_[0]->{dh_server_public};
}

sub error { @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error} }

sub is_encrypted {
    my $self = shift;

    return $self->session_type
      && $self->session_type ne 'no-encryption' ? 1 : 0;
}

1;
