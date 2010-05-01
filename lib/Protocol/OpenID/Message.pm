package Protocol::OpenID::Message;

use strict;
use warnings;

use overload '""' => sub { shift->to_string }, fallback => 1;

use Protocol::OpenID;
use Protocol::OpenID::Extension;

sub new {
    my $class = shift;

    my $self  = {};
    bless $self, $class;

    $self->{keys}   = [];
    $self->{params} = {};

    for (my $i = 0; $i < @_; $i += 2) {
        $self->param($_[$i] => $_[$i + 1]);
    }

    return $self;
}

sub build {
}

sub ns   { shift->param(ns   => @_) }
sub mode { shift->param(mode => @_) }

sub params { @_ > 1 ? $_[0]->{params} = $_[1] : $_[0]->{params} }

sub parse {
    my $self = shift;
    my $content = shift;

    $self->{keys} = [];
    $self->params({});

    unless ($content) {
        $self->error('Nothing to parse');
        return;
    }

    my @lines = split("\n", $content);

    foreach my $line (@lines) {
        unless ($line =~ m/^(.*?):(.*)/) {
            $self->param({});
            $self->error('Syntax error');
            return;
        }

        my ($name, $value) = ($1, $2);

        $self->param($name => $value);
    }

    return 1;
}

sub extensions {
    my $self = shift;

    my @ext = ();
    foreach my $key (@{$self->{keys}}) {
        next unless $key =~ m/^(?:openid\.)?ns\.(.*)/;

        push @ext, $1;
    }

    return @ext;
}

sub extension {
    my $self = shift;
    my $name = shift;

    if (@_) {
        my $ns     = $_[0]->{ns};
        my $params = $_[0]->{params};

        $self->param("ns.$name" => $ns);
        foreach my $key (keys %$params) {
            my $value = $params->{$key};
            $value = join(',', @$value) if ref($value) eq 'ARRAY';
            $self->param("$name.$key" => $value);
        }
    }
    else {
        my @extensions = $self->extensions;
        return unless grep {$_ eq $name} @extensions;

        my $ns = $self->param("ns.$name");

        my $params = {};
        foreach my $key (@{$self->{keys}}) {
            next unless $key =~ m/^(?:openid\.)?$name\.(.*)/;

            $params->{$1} = $self->param($key);
        }

        return Protocol::OpenID::Extension->new(
            name   => $name,
            ns     => $ns,
            params => $params
        );
    }
}

sub param {
    my $self  = shift;
    my $name  = shift;

    return unless $name;

    $name = "openid.$name" unless $name =~ m/^openid\./;

    if (@_ >= 1) {
        my $value = shift;

        $self->params->{$name} = $value;

        push @{$self->{keys}}, $name;

        return $self;
    }

    return $self->params->{$name};
}

sub to_hash {
    my $self = shift;

    $self->build;

    my $hash = {};

    foreach my $key (keys %{$self->params}) {
        $hash->{$key} = $self->param($key);
    }

    return $hash;
}

sub from_hash {
    my $self = shift;
    my $hash = shift;

    foreach my $key (keys %$hash) {
        my $value = $hash->{$key};

        $value = join(',', @$value) if ref($value) eq 'ARRAY';

        $self->param($key => $value);
    }

    return 1;
}

sub to_string {
    my $self = shift;

    $self->build;

    my $string = '';

    foreach my $key (@{$self->{keys}}) {
        $key =~ s/^openid\.//;
        my $value = $self->param($key);

        if (ref($value) && ref($value) eq 'ARRAY') {
            $value = join(',', @$value);
        }

        $string .=  $key . ':' . $value . "\n";
    }

    return $string;
}

sub error {
    @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error};
}

1;
