package Protocol::OpenID::Authentication::DirectRequest;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication::Response';

sub new {
    my $class = shift;
    my $response = shift;

    die 'Response object is required' unless $response;

    my $self = $class->SUPER::new;

    $self->from_hash($response->to_hash);

    return $self;
}

sub build {
    my $self = shift;

    $self->mode('check_authentication');
}

1;
