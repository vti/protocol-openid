#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 15;

use Protocol::OpenID::Transaction;
use Protocol::OpenID::Discoverer::HTML;

my $tx;

# Internal error
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 0, $headers, $body, "Can't connect");
      } => $tx => sub {
        my $tx = shift;

        is($tx->error, "Can't connect");
    }
);

# 404
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 404, $headers, $body);
      } => $tx => sub {
        my $tx = shift;

        is($tx->error, 'Wrong 404 response status');
    }
);

# No body
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 200, $headers, '');
      } => $tx => sub {
        my $tx = shift;

        is($tx->error, 'No body');
    }
);

# No head
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 200, $headers, 'foo bar');
      } => $tx => sub {
        my $tx = shift;

        is($tx->error, 'No <head>');
    }
);

# Wrong html
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 200, $headers, <<'EOF');
<head>
    <lik rel="oenid2.provider" hef="https://exampleprovider.om/server" />
</head>
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->error, 'No provider found');
    }
);

# OpenID 2.0
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 200, $headers, <<'EOF');
<head>
    <link rel="openid2.provider" href="https://exampleprovider.com/server" />
    <link rel="openid2.local_id" href="https://me.exampleprovider.com/" />
</head>
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->op_endpoint,         'https://exampleprovider.com/server');
        is($tx->op_local_identifier, 'https://me.exampleprovider.com/');
    }
);

# OpenID 1.1
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->($url, 200, $headers, <<'EOF');
<head>
    <link rel="openid.server" href="https://exampleprovider.com/server" />
    <link rel="openid.delegate" href="https://me.exampleprovider.com/" />
</head>
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->op_endpoint,         'https://exampleprovider.com/server');
        is($tx->op_local_identifier, 'https://me.exampleprovider.com/');
    }
);

# OpenID 1.1 with query
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->('http://1.1-with-query.exampleprovider.com/', 200, $headers, <<'EOF');
<head>
    <link rel="openid.server" href="https://exampleprovider.com/server?foo=bar" />
</head>
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->op_endpoint, 'https://exampleprovider.com/server?foo=bar');
        is($tx->op_local_identifier,
            'http://1.1-with-query.exampleprovider.com/');
    }
);

# Real life
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->('http://someone.blogspot.com/', 200, $headers, <<'EOF');
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
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->op_endpoint, 'http://www.blogger.com/openid-server.g');
        is($tx->op_local_identifier, 'http://someone.blogspot.com/');
    }
);

# Multi links
$tx = Protocol::OpenID::Transaction->new;
Protocol::OpenID::Discoverer::HTML->discover(
    sub {
        my ($url, $method, $headers, $body, $cb) = @_;

        $cb->('http://multi.exampleprovider.com/', 200, $headers, <<'EOF');
<head>
    <link rel="openid2.provider openid.server" href="https://exampleprovider.com/server" />
</head>
EOF
      } => $tx => sub {
        my $tx = shift;

        is($tx->op_endpoint,         'https://exampleprovider.com/server');
        is($tx->op_local_identifier, 'http://multi.exampleprovider.com/');
    }
);
