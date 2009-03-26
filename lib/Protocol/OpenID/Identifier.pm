package Protocol::OpenID::Identifier;
use Mouse;

use overload '""' => sub { shift->to_string }, fallback => 1;

require Carp;

has value => (
    isa => 'Str',
    is  => 'rw'
);

has type => (
    isa     => 'Str',
    is      => 'rw',
    default => 'URL'
);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new();

    if (my $value = shift) {
        $self->value($value);
    }

    return $self;
}

sub normalize {
    my $self = shift;

    my $value = $self->value;

    Carp::croak('value is required') unless $value;

    $value =~ s/^xri:\/\///;

    if ($value =~ m/^(?:=|@|\+|$|!|\()/) {
        $self->type('XRI');
    }
    else {
        $self->type('URL');

        # Make sure there is http:// or https://
        $value = 'http://' . $value unless $value =~ m/^https?:\/\//i;

        # Remove fragment
        $value =~ s/#.*$//;

        # Add leading slash
        if ($value =~ m/https?:\/\/[^\/]+$/) {
            $value .= '/';
        }
    }

    $self->value($value);

    return $self;
}

sub to_string {
    my $self = shift;

    $self->normalize->value;
}

1;
