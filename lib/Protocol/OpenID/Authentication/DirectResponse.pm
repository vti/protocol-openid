package Protocol::OpenID::Authentication::DirectResponse;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

use Protocol::OpenID;

sub is_valid          { shift->param(is_valid          => @_) }
sub invalidate_handle { shift->param(invalidate_handle => @_) }

sub parse {
    my $self = shift;

    my $ok = $self->SUPER::parse(@_);
    return unless $ok;

    return unless $self->ns && $self->ns eq OPENID_VERSION_2_0;

    return unless $self->is_valid && $self->is_valid =~ m/^(?:true|false)$/;

    return 1;
}

1;
