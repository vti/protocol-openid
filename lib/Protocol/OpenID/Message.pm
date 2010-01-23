package Protocol::OpenID::Message;

use strict;
use warnings;

use overload '""' => sub { shift->to_string }, fallback => 1;

use Protocol::OpenID;

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

        $self->param($1 => $2);
    }

    return 1;
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
        $self->param($key => $hash->{$key});
    }

    return 1;
}

sub to_string {
    my $self = shift;

    $self->build;

    my $string = '';

    foreach my $key (@{$self->{keys}}) {
        $key =~ s/^openid\.//;
        $string .=  $key . ':' . $self->param($key) . "\n";
    }

    return $string;
}

sub error {
    @_ > 1 ? $_[0]->{error} = $_[1] : $_[0]->{error};
}

1;
