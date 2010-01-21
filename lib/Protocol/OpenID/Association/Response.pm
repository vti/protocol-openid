package Protocol::OpenID::Association::Response;

use strict;
use warnings;

use base 'Protocol::OpenID::Association';

use Protocol::OpenID;

sub mac_key     { shift->param(mac_key     => @_) }
sub enc_mac_key { shift->param(enc_mac_key => @_) }
sub expires_in  { shift->param(expires_in  => @_) }
sub error_code  { shift->param(error_code  => @_) }

sub expires { @_ > 1 ? $_[0]->{expires} = $_[1] : $_[0]->{expires} }

sub parse {
    my $self = shift;

    my $ok = $self->SUPER::parse(@_);
    return unless $ok;

    unless ($self->ns && $self->ns eq OPENID_VERSION_2_0) {
        $self->error('Wrong OpenID 2.0 response');
        return;
    }

    # Check if it is unsuccessful response
    if ($self->param('error')) {

        # OP can suggest which session_type and assoc_type it supports
        # and we can try again unless we have already tried
        if (   $self->error_code
            && $self->error_code eq 'unsupported-type')
        {

            return 1;
        }

        # Parsing is ok, it is just error response
        return 1;
    }

    # Check if it is a successful response
    unless ($self->assoc_handle
        && $self->session_type
        && $self->assoc_type
        && $self->expires_in)
    {
        $self->error('Wrong association response');
        return;
    }

    # Check expires_in
    my $expires_in = $self->expires_in;
    unless ($expires_in =~ m/^\d+$/) {
        $self->error('Wrong expires_in');
        return;
    }

    # There are different fields returned when using/not using encryption
    if ($self->is_encrypted) {
        unless ($self->dh_server_public
            && $self->enc_mac_key)
        {
            $self->error(
                'Required dh_server_public ' . 'and enc_mac_key are missing');
            return;
        }
    }
    else {
        unless ($self->mac_key) {
            $self->error('Required mac_key is missing');
            return;
        }
    }

    # Check assoc_handle
    unless ($self->assoc_handle =~ m/^[\x21-\x86]{1,255}$/) {
        $self->error('Wrong assoc_handle');
        return;
    }

    $self->expires(time + $expires_in);

    return 1;
}

1;
