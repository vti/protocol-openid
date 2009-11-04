#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 8;

use Protocol::OpenID::Integer;

is(Protocol::OpenID::Integer->new(),      "");
is(Protocol::OpenID::Integer->new(0),     "\x00");
is(Protocol::OpenID::Integer->new(127),   "\x7F");
is(Protocol::OpenID::Integer->new(128),   "\x00\x80");
is(Protocol::OpenID::Integer->new(255),   "\x00\xFF");
is(Protocol::OpenID::Integer->new(32768), "\x00\x80\x00");
is(Protocol::OpenID::Integer->new(-1),    "");
is(Protocol::OpenID::Integer->new('foo'), "");
