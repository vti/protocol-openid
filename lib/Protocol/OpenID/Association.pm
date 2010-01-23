package Protocol::OpenID::Association;

use strict;
use warnings;

use Protocol::OpenID::Integer;

use Crypt::DH;
use Digest::SHA1 ();
use MIME::Base64 ();

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{p}
      ||= '0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E'
      . 'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557'
      . '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382'
      . '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';
    $self->{g} ||= 2;

    $self->{assoc_type}   ||= 'HMAC-SHA1';
    $self->{session_type} ||= 'DH-SHA1';

    if ($self->is_encrypted) {
        my $dh = $self->dh;

        my $integer = Protocol::OpenID::Integer->new($dh->pub_key);

        my $val = MIME::Base64::encode_base64("$integer");

        # Hack
        $val =~ s/\s+//g;

        $self->{dh_consumer_public} = $val;
    }

    return $self;
}

sub assoc_handle {
    @_ > 1 ? $_[0]->{assoc_handle} = $_[1] : $_[0]->{assoc_handle};
}
sub expires_in {
    @_ > 1 ? $_[0]->{expires_in} = $_[1] : $_[0]->{expires_in};
}
sub enc_mac_key {
    @_ > 1 ? $_[0]->{enc_mac_key} = $_[1] : $_[0]->{enc_mac_key};
}
sub mac_key {
    @_ > 1 ? $_[0]->{mac_key} = $_[1] : $_[0]->{mac_key};
}
sub error { @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error} }

sub p { @_ > 1 ? $_[0]->{p} = $_[1] : $_[0]->{p} }
sub g { @_ > 1 ? $_[0]->{g} = $_[1] : $_[0]->{g} }

sub dh {
    my $self = shift;

    return $self->{dh} if $self->{dh};

    my $dh = Crypt::DH->new;
    $dh->p($self->p);
    $dh->g($self->g);
    $dh->generate_keys;

    $self->{dh} = $dh;

    return $dh;
}

# Shortcuts
sub dh_consumer_public { shift->{dh_consumer_public} }
sub dh_server_public {
    @_ > 1 ? $_[0]->{dh_server_public} = $_[1] : $_[0]->{dh_server_public};
}
sub assoc_type         { shift->{assoc_type} }
sub session_type       { shift->{session_type} }

sub is_encrypted {
    my $self = shift;

    return $self->session_type
      && $self->session_type ne 'no-encryption' ? 1 : 0;
}

sub secret {
    my $self = shift;

    if ($self->session_type ne 'DH-SHA1') {
        return MIME::Base64::decode_base64($self->mac_key);
    }

    my $server_pub_key = MIME::Base64::decode_base64($self->dh_server_public);
    $server_pub_key = Protocol::OpenID::Integer->new->parse($server_pub_key);

    my $dh = $self->dh;

    my $dh_sec =
      Protocol::OpenID::Integer->new($dh->compute_secret($server_pub_key));

    # base64(H(btwoc(g ^ (xa * xb) mod p)) XOR MAC key) 
    my $secret =
      Digest::SHA1::sha1("$dh_sec")
      ^ MIME::Base64::decode_base64($self->enc_mac_key);

    # Not required, but easy to debug
    $secret = MIME::Base64::encode_base64($secret);
    $secret =~ s/\s+//g;

    return $secret;
}

sub to_hash {
    my $self = shift;

    my $hash = {};

    $hash->{assoc_handle} = $self->assoc_handle;
    $hash->{assoc_type} = $self->assoc_type;
    $hash->{session_type} = $self->session_type;

    if ($self->is_encrypted) {
        $hash->{secret} = $self->secret;
        $hash->{dh_consumer_public} = $self->dh_consumer_public;
        $hash->{dh_server_public} = $self->dh_server_public;
    }
    else {
        $hash->{secret} = $self->mac_key;
    }

    return $hash;
}

1;
