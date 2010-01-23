package Protocol::OpenID::Message::AssociationRequest;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

use Protocol::OpenID;

sub new {
    my $class = shift;
    my $assoc = shift;

    die 'Association object is required' unless $assoc;

    my $self = $class->SUPER::new(
        @_,
        assoc_type         => $assoc->assoc_type,
        session_type       => $assoc->session_type,
        dh_consumer_public => $assoc->dh_consumer_public
    );

    $self->{assoc} = $assoc;

    return $self;
}

sub dh_consumer_public { shift->param('dh_consumer_public') }
sub assoc_type         { shift->param('assoc_type') }
sub session_type       { shift->param('session_type') }
sub is_encrypted       { shift->{assoc}->is_encrypted }

sub build {
    my $self = shift;

    $self->ns(OPENID_VERSION_2_0);
    $self->mode('associate');

    return $self;
}

1;
