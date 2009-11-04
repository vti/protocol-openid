package Protocol::OpenID::Signature;

use strict;
use warnings;

use Protocol::OpenID::Parameters;
use Digest::SHA1 qw(sha1 sha1_hex);

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    $self->{params} ||= {};
    $self->{algorithm} ||= 'HMAC-SHA1';

    return $self;
}

sub params { defined $_[1] ? $_[0]->{params} = $_[1] : $_[0]->{params} }
sub algorithm {
    defined $_[1] ? $_[0]->{algorithm} = $_[1] : $_[0]->{algorithm};
}

sub keys {
    my $self = shift;

    return unless $self->params;

    my $signed = $self->params->{'openid.signed'};
    return unless $signed;

    return split(',', $signed);
}

sub calculate {
    my $self = shift;
    my $secret = shift;

    return unless $secret;

    my @keys = $self->keys;

    my $params = Protocol::OpenID::Parameters->new;
    foreach my $key (@keys) {
        $params->param($key => $self->params->{$key});
    }

    my $string = $params->to_string;

    return _hmac_sha1($string, $secret);
}

# From Digest::HMAC
sub _hmac_sha1_hex {
    unpack("H*", &_hmac_sha1);
}

sub _hmac_sha1 {
    _hmac($_[0], $_[1], \&sha1, 64);
}

sub _hmac {
    my($data, $key, $hash_func, $block_size) = @_;

    $block_size ||= 64;
    $key = &$hash_func($key) if length($key) > $block_size;

    my $k_ipad = $key ^ (chr(0x36) x $block_size);
    my $k_opad = $key ^ (chr(0x5c) x $block_size);

    &$hash_func($k_opad, &$hash_func($k_ipad, $data));
}

1;
