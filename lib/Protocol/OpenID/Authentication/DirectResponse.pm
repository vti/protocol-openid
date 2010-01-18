package Protocol::OpenID::Authentication::DirectResponse;

use strict;
use warnings;

use Protocol::OpenID;
use Protocol::OpenID::Parameters;

sub new {
    my $class = shift;

    my $self = {@_};
    bless $self, $class;

    return $self;
}

sub ns { @_ > 1 ? $_[0]->{ns} = $_[1] : $_[0]->{ns} }

sub is_valid { @_ > 1 ? $_[0]->{is_valid} = $_[1] : $_[0]->{is_valid} }

sub invalidate_handle {
    @_ > 1 ? $_[0]->{invalidate_handle} = $_[1] : $_[0]->{invalidate_handle};
}

sub parse {
    my $self = shift;
    my $data = shift;

    my $params = Protocol::OpenID::Parameters->new;

    return unless $params->parse($data);

    return unless $params->param('ns');

    return unless $params->param('ns') eq OPENID_VERSION_2_0;

    $self->ns($params->param('ns'));

    return unless $params->param('is_valid');

    if ($params->param('is_valid') eq 'true') {
        $self->is_valid(1);
    }
    elsif ($params->param('is_valid') eq 'false') {
        $self->is_valid(0);
    }
    else {
        return;
    }

    $self->invalidate_handle($params->param('invalidate_handle'))
      if $params->param('invalidate_handle');

    return $self;
}

1;
