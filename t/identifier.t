#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 39;

use_ok('Protocol::OpenID::Identifier');

my $id;

$id = Protocol::OpenID::Identifier->new;
ok(!$id->parse);

$id = Protocol::OpenID::Identifier->new;
ok(!$id->parse(''));

$id = Protocol::OpenID::Identifier->new;
ok(!$id->parse('print {};'));

$id = Protocol::OpenID::Identifier->new;
$id->type('URL');
$id->value('http://example.com/');
is("$id", 'http://example.com/');

$id->type(undef);
$id->value(undef);
is("$id", '');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('example.com'));
is("$id", 'http://example.com/',
    'URL. A URL with a missing scheme is normalized to a http URL');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://example.com'));
is("$id", 'http://example.com/',
    'URL.  An empty path component is normalized to a slash');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('https://example.com/'));
is("$id", 'https://example.com/', 'URL. https URLs remain https URLs');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://example.com/user'));
is("$id", 'http://example.com/user',
    'URL. No trailing slash is added to non-empty path components');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://example.com/user/'));
is("$id", 'http://example.com/user/',
    'URL. Trailing slashes are preserved on non-empty path components');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://example.com/'));
is("$id", 'http://example.com/',
    'URL.  Trailing slashes are preserved when the path is empty');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://EXAMPle.COm/'));
is("$id", 'http://example.com/',
    'URL.  Trailing slashes are preserved when the path is empty');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://EXAMPle.COm/FOO/BAR'));
is("$id", 'http://example.com/FOO/BAR',
    'URL.  Trailing slashes are preserved when the path is empty');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('http://example.com/#fragment'));
is("$id", 'http://example.com/', 'URL.  Fragment must be stripped off');
is($id->type, 'URL');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('=example'));
is("$id", '=example',
    'XRI. Normalized XRIs start with a global context symbol');
is($id->type, 'XRI');

$id = Protocol::OpenID::Identifier->new;
ok($id->parse('xri://=example'));
is("$id", '=example',
    'XRI Normalized XRIs start with a global context symbol');
is($id->type, 'XRI');
