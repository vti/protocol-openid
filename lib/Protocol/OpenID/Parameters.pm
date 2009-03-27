package Protocol::OpenID::Parameters;
use Mouse;

use overload '""' => sub { shift->to_string }, fallback => 1;

has params => (
    isa     => 'ArrayRef',
    is      => 'rw',
    default => sub { [] }
);

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new;

    if (@_ == 1) {
        $self->parse(@_);
    }
    elsif (@_ % 2 == 0) {
        for (my $i = 0; $i < @_; $i += 2) {
            $self->param($_[$i] => $_[$i + 1]);
        }
    }

    return $self;
}

sub parse {
    my $self = shift;
    my $content = shift;

    return unless $content;

    my @lines = split("\n", $content);

    foreach my $line (@lines) {
        next unless $line =~ m/^(.*?):(.*)/;

        $self->param($1 => $2);
    }

    return $self;
}

sub param {
    my $self  = shift;
    my $name  = shift;
    my $value = shift;

    return unless $name;

    my $params = $self->params;

    $name = "openid.$name" unless $name =~ m/^openid\./;

    my $i = 0;
    for (; $i < @$params; $i += 2) {
        last if $params->[$i] eq $name;
    }

    return $params->[$i + 1] unless $value;

    if ($i >= @$params) {
        push @$params, ($name => $value);
    }
    else {
        $params->[$i + 1] = $value;
    }

    return $self;
}

sub to_hash {
    my $self   = shift;

    my $hash = {};

    my $params = $self->params;

    for (my $i = 0; $i < @$params; $i += 2) {
        my $key = $params->[$i];

        $key =~ s/^openid\.//;

        $hash->{$key} = $params->[$i + 1];
    }

    return $hash;
}

sub to_string {
    my $self = shift;

    my $string = '';

    my $params = $self->params;
    for (my $i = 0; $i < @$params; $i += 2) {
        my $key = $params->[$i];
        $key =~ s/^openid\.//;
        $string .=  $key . ':' . $params->[$i + 1] . "\n";
    }

    return $string;
}

sub to_query {
    my $self = shift;

    my $string = '';

    my $params = $self->params;
    for (my $i = 0; $i < @$params; $i += 2) {
        my $key   = _url_escape($params->[$i]);
        my $value = _url_escape($params->[$i + 1]);

        $string .= '&' unless $i == 0;
        $string .= "$key=$value";
    }

    return $string;
}

sub _url_escape {
    my $string = shift;

    return unless $string;

    my $pattern = 'A-Za-z0-9\-\.\_\~';

    $string =~ s/([^$pattern])/sprintf('%%%02X',ord($1))/ge;

    return $string;
}

1;
