package Protocol::OpenID::Association;

use strict;
use warnings;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::OpenID::Integer;
use Protocol::OpenID::Parameters;

use Crypt::DH;
require MIME::Base64;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{assoc_type}   ||= 'HMAC-SHA1';
    $self->{session_type} ||= 'DH-SHA1';
    $self->{expires}      ||= 0;
    $self->{p}
      ||= '0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E'
      . 'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557'
      . '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382'
      . '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';
    $self->{g} ||= 2;

    return $self;
}

sub assoc_handle {
    @_ > 1 ? $_[0]->{assoc_handle} = $_[1] : $_[0]->{assoc_handle};
}

sub _is_retried {
    @_ > 1 ? $_[0]->{_is_retried} = $_[1] : $_[0]->{_is_retried};
}

sub http_req_cb {
    @_ > 1 ? $_[0]->{http_req_cb} = $_[1] : $_[0]->{http_req_cb};
}

sub assoc_type {
    @_ > 1 ? $_[0]->{assoc_type} = $_[1] : $_[0]->{assoc_type};
}

sub is_associated {
    @_ > 1 ? $_[0]->{is_associated} = $_[1] : $_[0]->{is_associated};
}

sub session_type {
    @_ > 1 ? $_[0]->{session_type} = $_[1] : $_[0]->{session_type};
}
sub expires { @_ > 1 ? $_[0]->{expires} = $_[1] : $_[0]->{expires} }

sub dh_server_public {
    @_ > 1
      ? $_[0]->{dh_server_public} = $_[1]
      : $_[0]->{dh_server_public};
}

sub enc_mac_key {
    @_ > 1 ? $_[0]->{enc_mac_key} = $_[1] : $_[0]->{enc_mac_key};
}
sub mac_key { @_ > 1 ? $_[0]->{mac_key} = $_[1] : $_[0]->{mac_key} }
sub p       { @_ > 1 ? $_[0]->{p}       = $_[1] : $_[0]->{p} }
sub g       { @_ > 1 ? $_[0]->{g}       = $_[1] : $_[0]->{g} }

sub error { @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error} }

sub is_encrypted {
    my $self = shift;

    return $self->session_type eq 'no-encryption' ? 0 : 1;
}

sub is_expired {
    my $self = shift;

    return time >= $self->expires ? 1 : 0;
}

sub dh_consumer_public {
    my $self = shift;

    return unless $self->is_encrypted;

    my $dh = Crypt::DH->new;
    $dh->p($self->p);
    $dh->g($self->g);
    $dh->generate_keys;

    my $integer = Protocol::OpenID::Integer->new($dh->pub_key);

    my $val = MIME::Base64::encode_base64("$integer");

    # Hack
    $val =~ s/\s+//g;

    return $val;
}

sub to_hash {
    my $self = shift;

    my $hash = {
        assoc_handle => $self->assoc_handle,
        assoc_type   => $self->assoc_type,
        session_type => $self->session_type,
        expires      => $self->expires,
    };

    if ($self->is_encrypted) {
        $hash->{dh_server_public}   = $self->dh_server_public;
        $hash->{dh_consumer_public} = $self->dh_consumer_public;
        $hash->{enc_mac_key}        = $self->enc_mac_key;
    }
    else {
        $hash->{mac_key} = $self->mac_key;
    }

    return $hash;
}

sub associate {
    my $self = shift;
    my ($op_endpoint_url, $cb) = @_;

    $self->error('');
    $self->is_associated(0);

    my $params = {
        'openid.ns'           => 'http://specs.openid.net/auth/2.0',
        'openid.mode'         => 'associate',
        'openid.assoc_type'   => $self->assoc_type,
        'openid.session_type' => $self->session_type
    };

    # If encrypted
    if (   $self->session_type eq 'DH-SHA1'
        || $self->session_type eq 'DH-SHA256')
    {
        $params->{'openid.dh_consumer_public'} = $self->dh_consumer_public;
    }

    $self->http_req_cb->(
        $op_endpoint_url,
        'POST',
        {},
        $params => sub {
            my ($op_endpoint_url, $status, $headers, $body) = @_;

            unless ($status && $status == 200) {
                $self->error("Wrong status: $status");
                return $cb->($self);
            }

            my $params = Protocol::OpenID::Parameters->new($body)->to_hash;

            unless (%$params
                && $params->{ns}
                && $params->{ns} eq 'http://specs.openid.net/auth/2.0')
            {
                $self->error('Wrong OpenID 2.0 response');
                return $cb->($self);
            }

            # Check if it is unsuccessful response
            if ($params->{error}) {

                # OP can suggest which session_type and assoc_type it supports
                # and we can try again unless we have already tried
                if (   $params->{error_code}
                    && $params->{error_code} eq 'unsupported-type')
                {
                    warn 'Association unsuccessful response' if DEBUG;

                    if (   $params->{session_type}
                        && $params->{assoc_type}
                        && !$self->_is_retried)
                    {
                        $self->session_type($params->{session_type});
                        $self->assoc_type($params->{assoc_type});

                        warn 'Try again to create association' if DEBUG;

                        $self->_is_retried(1);

                        return $self->associate(
                            $op_endpoint_url => sub {
                                my ($self) = @_;

                                return $cb->($self);
                            }
                        );
                    }
                }

                # Nothing we can do
                warn $params->{error} if DEBUG;
                $self->error($params->{error});
                return $cb->($self);
            }

            # Check if it is a successful response
            my $assoc_handle = $params->{assoc_handle};
            unless ($assoc_handle
                && $params->{session_type}
                && $params->{assoc_type}
                && $params->{expires_in})
            {
                $self->error('Wrong association response');
                return $cb->($self);
            }

            # Check the successful response itself
            if (   $params->{assoc_type} eq $self->assoc_type
                && $params->{session_type} eq $self->session_type)
            {

                # Check expires_in
                my $expires_in = $params->{expires_in};
                unless ($expires_in =~ m/^\d+$/) {
                    $self->error('Wrong expires_in');
                    return $cb->($self);
                }

                # There are different fields returned when using/not using
                # encryption
                if ($self->is_encrypted) {
                    unless ($params->{dh_server_public}
                        && $params->{enc_mac_key})
                    {
                        $self->error('Required dh_server_public '
                              . 'and enc_mac_key are missing');
                        return $cb->($self);
                    }

                    $self->dh_server_public($params->{dh_server_public});
                    $self->enc_mac_key($params->{enc_mac_key});
                }
                else {
                    unless ($params->{mac_key}) {
                        $self->error('Required mac_key is missing');
                        return $cb->($self);
                    }
                    $self->mac_key($params->{mac_key});
                }

                # Check assoc_handle
                unless ($assoc_handle =~ m/^[\x21-\x86]{1,255}$/) {
                    $self->error('Wrong assoc_handle');
                    return $cb->($self);
                }

                # Save association
                $self->assoc_handle($assoc_handle);
                $self->expires(time + $expires_in);

                warn 'Association successful response' if DEBUG;

                $self->is_associated(1);

                return $cb->($self);
            }

            $self->error('Association response is not equal to request');
            return $cb->($self);
        }
    );
}

1;
