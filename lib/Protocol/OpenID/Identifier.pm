package Protocol::OpenID::Identifier;

use strict;
use warnings;

use overload '""' => sub { shift->to_string }, fallback => 1;

require Carp;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    if (my $value = shift) {
        $self->parse($value);
    }

    $self->{type} ||= 'URL';

    return $self;
}

sub value { defined $_[1] ? $_[0]->{value} = $_[1] : $_[0]->{value} }
sub type  { defined $_[1] ? $_[0]->{type}  = $_[1] : $_[0]->{type} }

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
