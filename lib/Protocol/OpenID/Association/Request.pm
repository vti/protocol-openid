package Protocol::OpenID::Association::Request;

use strict;
use warnings;

use base 'Protocol::OpenID::Association';

use Protocol::OpenID;
use Protocol::OpenID::Integer;

use Crypt::DH;
require MIME::Base64;

sub dh_consumer_public { shift->param(dh_consumer_public => @_) }

sub new {
    my $self = shift->SUPER::new(@_);

    $self->assoc_type('HMAC-SHA1') unless $self->assoc_type;
    $self->session_type('DH-SHA1') unless $self->session_type;
    $self->{p}
      ||= '0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E'
      . 'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557'
      . '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382'
      . '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB';
    $self->{g} ||= 2;

    return $self;
}

sub p { @_ > 1 ? $_[0]->{p} = $_[1] : $_[0]->{p} }
sub g { @_ > 1 ? $_[0]->{g} = $_[1] : $_[0]->{g} }

sub build {
    my $self = shift;

    $self->ns(OPENID_VERSION_2_0);
    $self->mode('associate');

    if ($self->is_encrypted) {
        my $dh = Crypt::DH->new;
        $dh->p($self->p);
        $dh->g($self->g);
        $dh->generate_keys;

        my $integer = Protocol::OpenID::Integer->new($dh->pub_key);

        my $val = MIME::Base64::encode_base64("$integer");

        # Hack
        $val =~ s/\s+//g;

        $self->dh_consumer_public($val);
    }
}

1;
