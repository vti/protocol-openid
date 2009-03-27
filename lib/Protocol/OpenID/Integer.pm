package Protocol::OpenID::Integer;
use Mouse;

use overload '""' => sub { shift->to_string }, fallback => 1;

require Carp;
use Math::BigInt;

has int => (
    isa => 'Math::BigInt',
    is  => 'rw'
);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new();

    my $int = shift;

    $int = Math::BigInt->new($int) unless ref $int;

    Carp::croak("Can't deal with negative numbers") if $int->is_negative;

    $self->int($int);

    return $self;
}

sub to_string {
    my $self = shift;

    my $bits = $self->int->as_bin;
    die unless $bits =~ s/^0b//;

    # prepend zeros to round to byte boundary, or to unset high bit
    my $prepend = (8 - length($bits) % 8) || ($bits =~ /^1/ ? 8 : 0);
    $bits = ("0" x $prepend) . $bits if $prepend;

    return pack("B*", $bits);
}

1;
