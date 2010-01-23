package Protocol::OpenID::Message::AssociationResponse;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

use Protocol::OpenID;
use Protocol::OpenID::Integer;

sub new {
    my $class = shift;
    my $assoc = shift;

    die 'Association object is required' unless $assoc;

    my $self = $class->SUPER::new(@_);

    $self->{assoc} = $assoc;

    return $self;
}

sub assoc_handle { shift->param('assoc_handle') }
sub assoc_type   { shift->param('assoc_type') }
sub session_type { shift->param('session_type') }
sub mac_key      { shift->param('mac_key') }
sub enc_mac_key  { shift->param('enc_mac_key') }
sub expires_in   { shift->param('expires_in') }
sub error_code   { shift->param('error_code') }
sub is_encrypted { shift->{assoc}->is_encrypted }

sub dh_server_public { shift->param(dh_server_public => @_) }

sub expires { @_ > 1 ? $_[0]->{expires} = $_[1] : $_[0]->{expires} }

sub parse {
    my $self = shift;

    my $ok = $self->SUPER::parse(@_);
    return unless $ok;

    unless ($self->ns && $self->ns eq OPENID_VERSION_2_0) {
        $self->error('Wrong OpenID 2.0 response');
        return;
    }

    # Check if it is unsuccessful response
    if ($self->param('error')) {
        $self->{assoc}->error($self->param('error'));

        # OP can suggest which session_type and assoc_type it supports
        # and we can try again unless we have already tried
        if (   $self->error_code
            && $self->error_code eq 'unsupported-type')
        {
            return 1;
        }

        # Parsing is ok, it is just error response
        return 1;
    }

    # Check if it is a successful response
    unless ($self->assoc_handle
        && $self->session_type
        && $self->assoc_type
        && $self->session_type eq $self->{assoc}->session_type
        && $self->assoc_type eq $self->{assoc}->assoc_type
        && $self->expires_in)
    {
        $self->error('Wrong association response');
        return;
    }

    # Check expires_in
    my $expires_in = $self->expires_in;
    unless ($expires_in =~ m/^\d+$/) {
        $self->error('Wrong expires_in');
        return;
    }

    # There are different fields returned when using/not using encryption
    if ($self->is_encrypted) {
        unless ($self->dh_server_public
            && $self->enc_mac_key)
        {
            $self->error(
                'Required dh_server_public ' . 'and enc_mac_key are missing');
            return;
        }
    }
    else {
        unless ($self->mac_key) {
            $self->error('Required mac_key is missing');
            return;
        }
    }

    # Check assoc_handle
    unless ($self->assoc_handle =~ m/^[\x21-\x86]{1,255}$/) {
        $self->error('Wrong assoc_handle');
        return;
    }

    $self->expires(time + $expires_in);

    $self->{assoc}->assoc_handle($self->assoc_handle);
    $self->{assoc}->expires_in($self->expires_in);

    if ($self->is_encrypted) {
        $self->{assoc}->enc_mac_key($self->enc_mac_key);
        $self->{assoc}->dh_server_public($self->dh_server_public);
    }
    else {
        $self->{assoc}->mac_key($self->mac_key);
    }

    return 1;
}

1;
