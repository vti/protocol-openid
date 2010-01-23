package Protocol::OpenID::Integer;

use strict;
use warnings;

use overload '""' => sub { shift->to_string }, fallback => 1;

require Carp;
use Math::BigInt;

sub new {
    my $class = shift;

    my $self  = {};
    bless $self, $class;

    my $int = shift;

    if (defined $int) {
        $int = Math::BigInt->new($int) unless ref $int;

        $self->int($int) unless $int->is_negative;
    }

    return $self;
}

sub int { @_ > 1 ? $_[0]->{int} = $_[1] : $_[0]->{int} }

sub parse {
    my $self = shift;
    my $string = shift;

    my $int = "0b" . unpack("B*", $string);

    $int = Math::BigInt->new($int) unless ref $int;

    $self->int($int);

    return $self->int;
}

sub to_string {
    my $self = shift;

    return '' unless defined $self->int;

    my $bits = $self->int->as_bin;
    return '' unless $bits =~ s/^0b//;

    # prepend zeros to round to byte boundary, or to unset high bit
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;

    return pack("B*", $bits);
}

1;
