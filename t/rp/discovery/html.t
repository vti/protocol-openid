use Test::More tests => 14;
use strict;
use warnings;

use_ok('Protocol::OpenID::Discovery::HTML');

use Protocol::OpenID::RP;
use Protocol::OpenID::Discovery;
use Protocol::OpenID::Identifier;

my $rp = Protocol::OpenID::RP->new(
    return_to => 'http://foo.bar',
    http_req_cb => sub {
        my ($self, $url, $args, $cb) = @_;

        my $body;
        my $status = 200;
        my $headers;

        if ($url eq 'http://nobody.exampleprovider.com/') {
        }
        elsif ($url eq 'http://wronghtml.exampleprovider.com/') {
            $body = <<'';
foo bar

        }
        elsif ($url eq 'http://exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider" href="https://exampleprovider.com/server" />
    <link rel="openid2.local_id" href="https://me.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://1.1.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" href="https://exampleprovider.com/server" />
    <link rel="openid.delegate" href="https://me.exampleprovider.com/" />
</head>

        }
        elsif ($url eq 'http://1.1-with-query.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid.server" href="https://exampleprovider.com/server?foo=bar" />
</head>

        }
        elsif ($url eq 'http://someone.blogspot.com/') {
            $body = <<'';
<head>
<script type="text/javascript">(function() { var a=window;function d(){this.t={};this.tick=function(b,c){this.t[b]=[(new Date).getTime(),c]};this.tick("start")}var e=new d;a.jstiming={Timer:d,load:e};try{a.jstiming.pt=a.external.pageT}catch(f){};function g(b){var c=0;if(b.offsetParent){do c+=b.offsetTop;while(b=b.offsetParent)}return c}a.tickAboveFold=function(b){g(b)<=750&&a.jstiming.load.tick("aft")};var h=false;function i(){if(!h){h=true;a.jstiming.load.tick("firstScrollTime")}}a.addEventListener?a.addEventListener("scroll",i,false):a.attachEvent("onscroll",i); })();</script>
<meta content='text/html; charset=UTF-8' http-equiv='Content-Type'/>
<meta content='true' name='MSSmartTagsPreventParsing'/>
<meta content='blogger' name='generator'/>
<link href='http://www.blogger.com/favicon.ico' rel='icon' type='image/vnd.microsoft.icon'/>
<link rel="alternate" type="application/atom+xml" title="Blog - Atom" href="http://vti-vti.blogspot.com/feeds/posts/default" />
<link rel="alternate" type="application/rss+xml" title="Blog - RSS" href="http://vti-vti.blogspot.com/feeds/posts/default?alt=rss" />
<link rel="service.post" type="application/atom+xml" title="Blog - Atom" href="http://www.blogger.com/feeds/8035268290765043101/posts/default" />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://www.blogger.com/rsd.g?blogID=8035268290765043101" />
<link rel="me" href="http://www.blogger.com/profile/02408119773154487013" />
<link rel="openid.server" href="http://www.blogger.com/openid-server.g" />
</head>

        }
        #elsif ($url eq 'http://1.1.html2.exampleprovider.com/') {
            #$body = <<'';
#<head>
    #<link rel="openid.server" href="https://www.exampleprovider.com/" />
#</head>

        #}
        #elsif ($url eq 'http://html2.exampleprovider.com/') {
            #$body = <<'';
#<head>
    #<link rel="openid2.provider" href="https://www.exampleprovider.com/" />
#</head>

        #}
        elsif ($url eq 'http://multi.exampleprovider.com/') {
            $body = <<'';
<head>
    <link rel="openid2.provider openid.server" href="https://exampleprovider.com/server" />
</head>

        }
        else {
            $status = 404;
        }

        $cb->($self => $url =>
              {status => $status, headers => $headers, body => $body});
    }
);

my $identifier = Protocol::OpenID::Identifier->new;
my $hook = \&Protocol::OpenID::Discovery::HTML::hook;
my $ctl = Async::Hooks::Ctl->new;

# 404
$hook->($ctl, [$rp, $identifier->parse('404.exampleprovider.com')]);
ok(not defined $rp->discovery);

# No body
$hook->($ctl, [$rp, $identifier->parse('nobody.exampleprovider.com')]);
ok(not defined $rp->discovery);

# Wrong html
$hook->($ctl, [$rp, $identifier->parse('wronghtml.exampleprovider.com')]);
ok(not defined $rp->discovery);

$hook->($ctl, [$rp, $identifier->parse('http://exampleprovider.com/')]);
is($rp->discovery->op_endpoint, 'https://exampleprovider.com/server');
is($rp->discovery->op_local_identifier, 'https://me.exampleprovider.com/');
$rp->discovery->clear;

$hook->($ctl, [$rp, $identifier->parse('http://1.1.exampleprovider.com/')]);
is($rp->discovery->op_endpoint, 'https://exampleprovider.com/server');
is($rp->discovery->op_local_identifier, 'https://me.exampleprovider.com/');
$rp->discovery->clear;

$hook->($ctl, [$rp, $identifier->parse('http://1.1-with-query.exampleprovider.com/')]);
is($rp->discovery->op_endpoint, 'https://exampleprovider.com/server?foo=bar');
is($rp->discovery->op_local_identifier, 'http://1.1-with-query.exampleprovider.com/');
$rp->discovery->clear;

$hook->($ctl, [$rp, $identifier->parse('http://multi.exampleprovider.com/')]);
is($rp->discovery->op_endpoint, 'https://exampleprovider.com/server');
is($rp->discovery->op_local_identifier, 'http://multi.exampleprovider.com/');
$rp->discovery->clear;

$hook->($ctl, [$rp, $identifier->parse('http://someone.blogspot.com/')]);
is($rp->discovery->op_endpoint, 'http://www.blogger.com/openid-server.g');
is($rp->discovery->op_local_identifier, 'http://someone.blogspot.com/');
$rp->discovery->clear;

#$hook->($ctl, [$rp, $identifier->parse('http://1.1.html.exampleprovider.com/')]);
#$hook->($ctl, [$rp, $identifier->parse('http://1.1-with-query.html.exampleprovider.com/')]);
#$hook->($ctl, [$rp, $identifier->parse('http://1.1.html2.exampleprovider.com/')]);

#$hook->($ctl, [$rp, $identifier->parse('http://html2.exampleprovider.com/')]);
#$hook->($ctl, [$rp, $identifier->parse('http://html4.exampleprovider.com/')]);
