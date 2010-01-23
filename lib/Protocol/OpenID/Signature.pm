package Protocol::OpenID::Signature;

use strict;
use warnings;

use Protocol::OpenID::Message;
use Digest::SHA1 qw(sha1 sha1_hex);
use MIME::Base64 ();

sub new {
    my $class = shift;
    my $hash  = shift;

    my $self = {message => $hash, @_};
    bless $self, $class;

    $self->{algorithm} ||= 'HMAC-SHA1';

    return $self;
}

sub algorithm { @_ > 1 ? $_[0]->{algorithm} = $_[1] : $_[0]->{algorithm}; }

sub keys {
    my $self = shift;

    return unless $self->{message};

    my $signed = $self->{message}->{'openid.signed'};
    return unless $signed;

    return split(',', $signed);
}

sub calculate {
    my $self   = shift;
    my $secret = shift;

    return unless $secret;

    $secret = MIME::Base64::decode_base64($secret);

    my @keys = $self->keys;

    my $message = Protocol::OpenID::Message->new;
    foreach my $key (@keys) {
        $message->param($key => $self->{message}->{"openid.$key"});
    }

    my $string = $message->to_string;

    my $sig = MIME::Base64::encode_base64(_hmac_sha1($string, $secret));
    $sig =~ s/\s+//g;

    return $sig
}

# From Digest::HMAC
sub _hmac_sha1_hex {
    unpack("H*", &_hmac_sha1);
}

sub _hmac_sha1 {
    _hmac($_[0], $_[1], \&sha1, 64);
}

sub _hmac {
    my ($data, $key, $hash_func, $block_size) = @_;

    $block_size ||= 64;
    $key = &$hash_func($key) if length($key) > $block_size;

    my $k_ipad = $key ^ (chr(0x36) x $block_size);
    my $k_opad = $key ^ (chr(0x5c) x $block_size);

    &$hash_func($k_opad, &$hash_func($k_ipad, $data));
}

1;
