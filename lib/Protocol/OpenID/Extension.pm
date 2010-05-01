package Protocol::OpenID::Extension;

use strict;
use warnings;

use Protocol::OpenID;

sub new {
    my $class = shift;
    my %params = @_;

    my $name = $params{name};
    my $ns   = $params{ns};

    die 'Extension name is required' unless $name;
    die 'Extension ns is required' unless $ns;

    my $self  = {params => $params{params} || {}};
    bless $self, $class;

    foreach my $param (keys %{$self->{params}}) {
        my $value = $self->{params}->{$param};
        next unless ref $value;

        $value = join(',', @$value);
        $self->{params}->{$param} = $value;
    }

    $self->{name} = $name;
    $self->{ns} = $ns;

    return $self;
}

sub name   { shift->{name} }
sub ns     { shift->{ns} }
sub params { shift->{params} }

#sub to_hash {
#    my $self = shift;
#
#    my $name = $self->{name};
#
#    my $hash = {};
#
#    $hash->{"openid.ns.$name"} = $self->{ns};
#
#    foreach my $key (keys %{$self->{params}}) {
#        $hash->{"openid.$name.$key"} = $self->{params}->{$key};
#    }
#
#    return $hash;
#}
#
#sub from_hash {
#    my $self = shift;
#    my $hash = shift;
#
#    foreach my $key (keys %$hash) {
#        my $value = $hash->{$key};
#
#        $value = join(',', @$value) if ref($value) eq 'ARRAY';
#
#        $self->{params}->{$key} = $value;
#    }
#
#    return 1;
#}

1;
