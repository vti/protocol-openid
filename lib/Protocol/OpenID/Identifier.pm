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
        $self->parse($value);
    }

    return $self;
}

sub parse {
    my $self = shift;
    my $value = shift;

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

        my ($base, $path) = ($value =~ m/^(https?:\/\/[^\/]+)(.*)/);

        $value = lc $base;

        # Add leading slash
        $value .= '/' unless $path;

        $value .= $path if $path;
    }

    $self->value($value);

    return $self;
}

sub to_string {
    my $self = shift;

    $self->value;
}

1;
