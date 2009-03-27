package Protocol::OpenID::Signature;

use strict;
use warnings;

use base 'Mojo::Base';

use Protocol::OpenID::Message;
use Digest::SHA1 qw(sha1 sha1_hex);

__PACKAGE__->attr(signed => (chained => 1));
__PACKAGE__->attr(params => (default => sub { {} }));

sub calculate {
    my $self = shift;

    return unless $self->signed;

    my $message = Protocol::OpenID::Message->new;

    my $params = $self->params;
    my @keys = split(',', $self->signed);
    foreach my $key (@keys) {
        $message->param($key => $params->{"openid.$key"});
    }

    my $string = $message->to_string;

    return _hmac_sha1($string, 'secret');
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
