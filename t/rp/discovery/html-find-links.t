use Test::More tests => 9;

use_ok('Protocol::OpenID::Discovery::HTML');

my $cb = \&Protocol::OpenID::Discovery::HTML::_html_tag;

my $html = '';
is_deeply($cb->(\$html), []);

$html = '<link />';
is_deeply($cb->(\$html), [{name => 'link', attrs => undef, content => ''}]);

$html = '<link rel="foo" />';
is_deeply($cb->(\$html),
    [{name => 'link', attrs => {rel => 'foo'}, content => ''}]);

$html = '<link rel="foo">';
is_deeply($cb->(\$html),
    [{name => 'link', attrs => {rel => 'foo'}, content => ''}]);

$html = '<link rel="foo bar">';
is_deeply($cb->(\$html),
    [{name => 'link', attrs => {rel => 'foo bar'}, content => ''}]);

$html = '<link rel="foo bar"><link rel="bar" />';
is_deeply(
    $cb->(\$html),
    [   {name => 'link', attrs => {rel => 'foo bar'}, content => ''},
        {name => 'link', attrs => {rel => 'bar'},     content => ''}
    ]
);

$html = '<script>1 > 2</script><link rel="foo">';
is_deeply(
    $cb->(\$html),
    [{name => 'link', content => '', attrs => {rel => 'foo'}}]
);

$html = '<!-- <link rel="foo" /> --><link rel="foo">';
is_deeply(
    $cb->(\$html),
    [{name => 'link', content => '', attrs => {rel => 'foo'}}]
);
