package Protocol::OpenID::Association::Response;

use strict;
use warnings;

use base 'Protocol::OpenID::Association';

use Protocol::OpenID::Parameters;

sub mac_key { @_ > 1 ? $_[0]->{mac_key} = $_[1] : $_[0]->{mac_key} }

sub enc_mac_key {
    @_ > 1 ? $_[0]->{enc_mac_key} = $_[1] : $_[0]->{enc_mac_key};
}

sub expires { @_ > 1 ? $_[0]->{expires} = $_[1] : $_[0]->{expires} }

sub expires_in { @_ > 1 ? $_[0]->{expires_in} = $_[1] : $_[0]->{expires_in} }

sub parse {
    my $self = shift;
    my ($body) = @_;

    my $params = Protocol::OpenID::Parameters->new($body)->to_hash;

    unless (%$params
        && $params->{ns}
        && $params->{ns} eq 'http://specs.openid.net/auth/2.0')
    {
        $self->error('Wrong OpenID 2.0 response');
        return;
    }

    # Check if it is unsuccessful response
    if ($params->{error}) {

        # Nothing we can do
        $self->error($params->{error});

        # OP can suggest which session_type and assoc_type it supports
        # and we can try again unless we have already tried
        if (   $params->{error_code}
            && $params->{error_code} eq 'unsupported-type')
        {
            if ($params->{session_type} && $params->{assoc_type}) {
                $self->session_type($params->{session_type});
                $self->assoc_type($params->{assoc_type});
            }

            return 1;
        }

        # Parsing is ok, it is just error response
        return 1;
    }

    # Check if it is a successful response
    my $assoc_handle = $params->{assoc_handle};
    unless ($assoc_handle
        && $params->{session_type}
        && $params->{assoc_type}
        && $params->{expires_in})
    {
        $self->error('Wrong association response');
        return;
    }

    $self->session_type($params->{session_type});
    $self->assoc_type($params->{assoc_type});

    # Check expires_in
    my $expires_in = $params->{expires_in};
    unless ($expires_in =~ m/^\d+$/) {
        $self->error('Wrong expires_in');
        return;
    }

    # There are different fields returned when using/not using encryption
    if ($self->is_encrypted) {
        unless ($params->{dh_server_public}
            && $params->{enc_mac_key})
        {
            $self->error(
                'Required dh_server_public ' . 'and enc_mac_key are missing');
            return;
        }

        $self->dh_server_public($params->{dh_server_public});
        $self->enc_mac_key($params->{enc_mac_key});
    }
    else {
        unless ($params->{mac_key}) {
            $self->error('Required mac_key is missing');
            return;
        }

        $self->mac_key($params->{mac_key});
    }

    # Check assoc_handle
    unless ($assoc_handle =~ m/^[\x21-\x86]{1,255}$/) {
        $self->error('Wrong assoc_handle');
        return;
    }

    # Save association
    $self->assoc_handle($assoc_handle);
    $self->expires_in($expires_in);
    $self->expires(time + $expires_in);

    return 1;
}

1;
