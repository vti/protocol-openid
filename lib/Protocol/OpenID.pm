package Protocol::OpenID;
use Moose;

use Async::Hooks;

# Hook chains
has hooks => (
    isa     => 'Async::Hooks',
    default => sub { Async::Hooks->new },
    is      => 'ro',
    lazy    => 1,
    handles => [qw( hook call )],
);

has error => (
    isa => 'Str',
    is  => 'rw'
);

1;
