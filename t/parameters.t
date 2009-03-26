use Test::More tests => 15;

use Protocol::OpenID::Parameters;

my $p = Protocol::OpenID::Parameters->new;
is_deeply($p->params, []);

$p->params([]);
is_deeply($p->params, []);

$p->param(ns => 'foo');
is($p->params->[0], 'openid.ns');
is($p->params->[1], 'foo');
is($p->param('ns'), 'foo');

$p->param(ns => 'bar');
is($p->params->[0], 'openid.ns');
is($p->params->[1], 'bar');
is($p->param('ns'), 'bar');


$p->params([]);
$p->param(foo => 'bar');
$p->param(baz => 'foo');

is_deeply($p->to_hash, {'openid.foo' => 'bar', 'openid.baz' => 'foo'});
is_deeply($p->to_hash, {'openid.foo' => 'bar', 'openid.baz' => 'foo'});

$p = Protocol::OpenID::Parameters->new('ns:http://specs.openid.net/auth/2.0');
is($p->param('ns'), 'http://specs.openid.net/auth/2.0');

$p->parse(<<"");
ns:http://specs.openid.net/auth/2.0
error:hello

is($p->param('ns'), 'http://specs.openid.net/auth/2.0');
is($p->param('error'), 'hello');

is($p->to_string, "ns:http://specs.openid.net/auth/2.0\nerror:hello\n");

is($p->to_query, "openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.error=hello");
