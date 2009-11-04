package Protocol::OpenID::Association;

use strict;
use warnings;

use Protocol::OpenID::Integer;

use Crypt::DH;
require MIME::Base64;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{assoc_type}   ||= 'HMAC-SHA1';
    $self->{session_type} ||= 'DH-SHA1';
    $self->{expires}      ||= 0;
    $self->{p} ||=
        '0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E'
      . 'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557'
      . '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382'
      . '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';
    $self->{g} ||= 2;

    return $self;
}

sub assoc_handle {
    defined $_[1] ? $_[0]->{assoc_handle} = $_[1] : $_[0]->{assoc_handle};
}

sub assoc_type {
    defined $_[1] ? $_[0]->{assoc_type} = $_[1] : $_[0]->{assoc_type};
}

sub session_type {
    defined $_[1] ? $_[0]->{session_type} = $_[1] : $_[0]->{session_type};
}
sub expires { defined $_[1] ? $_[0]->{expires} = $_[1] : $_[0]->{expires} }

sub dh_server_public {
    defined $_[1]
      ? $_[0]->{dh_server_public} = $_[1]
      : $_[0]->{dh_server_public};
}

sub enc_mac_key {
    defined $_[1] ? $_[0]->{enc_mac_key} = $_[1] : $_[0]->{enc_mac_key};
}
sub mac_key { defined $_[1] ? $_[0]->{mac_key} = $_[1] : $_[0]->{mac_key} }
sub p       { defined $_[1] ? $_[0]->{p}       = $_[1] : $_[0]->{p} }
sub g       { defined $_[1] ? $_[0]->{g}       = $_[1] : $_[0]->{g} }

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

1;
