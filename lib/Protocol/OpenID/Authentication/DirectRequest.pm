package Protocol::OpenID::Authentication::DirectRequest;

use strict;
use warnings;

use base 'Protocol::OpenID::Authentication::Response';

sub new {
    my $class    = shift;
    my $response = shift;

    die 'Response object is required' unless $response;

    my %params = %{$response->to_hash};
    %params =
      map { $_ => $params{"openid.$_"} }
      map { s/^openid\.//; $_ } keys %params;

    my $self = {%params};
    bless $self, $class;

    $self->mode('check_authentication');

    return $self;
}

1;
