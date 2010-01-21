package Protocol::OpenID::Association;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

sub assoc_handle     { shift->param(assoc_handle     => @_) }
sub assoc_type       { shift->param(assoc_type       => @_) }
sub session_type     { shift->param(session_type     => @_) }
sub dh_server_public { shift->param(dh_server_public => @_) }

sub is_encrypted {
    my $self = shift;

    return $self->session_type
      && $self->session_type ne 'no-encryption' ? 1 : 0;
}

1;
