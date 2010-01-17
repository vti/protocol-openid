package Protocol::OpenID::Discoverer::Base;

use strict;
use warnings;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    return $self;
}

sub discover { die 'Must be implemented' }

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub error { @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error} }

1;
