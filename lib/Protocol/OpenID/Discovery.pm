package Protocol::OpenID::Discovery;
use Mouse;

our $VERSION_1_0 = 'http://openid.net/signon/1.0';
our $VERSION_1_1 = 'http://openid.net/signon/1.1';
our $VERSION_2_0 = 'http://specs.openid.net/auth/2.0';

has op_identifier => (
    isa     => 'Str',
    is      => 'rw'
);

has protocol_version => (
    isa     => 'Str',
    is      => 'rw',
    default => $VERSION_2_0
);

has op_endpoint => (
    isa => 'Str',
    is  => 'rw'
);

has claimed_identifier => (
    isa     => 'Str',
    is      => 'rw',
    default => 'http://specs.openid.net/auth/2.0/identifier_select'
);

has op_local_identifier => (
    isa     => 'Str',
    is      => 'rw',
    default => 'http://specs.openid.net/auth/2.0/identifier_select'
);

sub clear {
    my $self = shift;


    return $self;
}

1;
