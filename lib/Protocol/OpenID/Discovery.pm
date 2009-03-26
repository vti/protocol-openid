package Protocol::OpenID::Discovery;
use Mouse;

has op_identifier => (
    isa     => 'Str',
    is      => 'rw'
);

has protocol_version => (
    isa     => 'Int',
    is      => 'rw',
    default => 2
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

1;
