package Protocol::OpenID::Identifier;

use strict;
use warnings;

use overload '""' => sub { shift->to_string }, fallback => 1;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{value} = '';

    my $value = shift;
    if (defined $value) {
        $self->parse($value);
    }

    $self->{type} ||= 'URL';

    return $self;
}

sub value { @_ > 1 ? $_[0]->{value} = $_[1] : $_[0]->{value} }
sub type  { @_ > 1 ? $_[0]->{type}  = $_[1] : $_[0]->{type} }

sub parse {
    my $self = shift;
    my $value = shift;

    return $self unless $value;

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
