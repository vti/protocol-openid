package Protocol::OpenID::Signature;
use Mouse;

use Protocol::OpenID::Parameters;
use Digest::SHA1 qw(sha1 sha1_hex);

has params => (
    isa     => 'Protocol::OpenID::Parameters',
    is      => 'rw'
);

has algorithm => (
    isa     => 'Str',
    is      => 'rw',
    default => 'HMAC-SHA1'
);

sub keys {
    my $self = shift;

    return unless $self->params;

    my $signed = $self->params->param('signed');
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
        $params->param($key => $self->params->param($key));
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
