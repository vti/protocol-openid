use Test::More tests => 6;

use Protocol::OpenID::Nonce;

my $nonce = Protocol::OpenID::Nonce->new;

ok($nonce->parse('2009-03-23T14:40:38ZUNIQUE'));

is($nonce->epoch, '1237819238');
is($nonce->tail,  'UNIQUE');

is("$nonce", '2009-03-23T14:40:38ZUNIQUE');

$nonce = Protocol::OpenID::Nonce->new(1237819238);
$nonce->tail('ABCD');
is("$nonce", '2009-03-23T14:40:38ZABCD');

ok(not defined $nonce->parse('foo bar'));
