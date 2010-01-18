package Protocol::OpenID::Authentication;

use strict;
use warnings;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    return $self;
}

sub ns { @_ > 1 ? $_[0]->{ns} = $_[1] : $_[0]->{ns} }

sub assoc_handle {
    @_ > 1 ? $_[0]->{assoc_handle} = $_[1] : $_[0]->{assoc_handle};
}

sub error {
    @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error};
}

1;
