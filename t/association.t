use Test::More tests => 8;

use_ok('Protocol::OpenID::Association');

my $a = Protocol::OpenID::Association->new;

ok($a->is_encrypted);
ok($a->is_expired);
ok($a->dh_consumer_public);

$a->session_type('no-encryption');
ok(!$a->is_encrypted);

$a->expires(time - 2);
ok($a->is_expired);

$a->expires(time + 2);
ok(!$a->is_expired);

ok(not defined $a->dh_consumer_public);
