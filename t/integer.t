#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 13;

use Protocol::OpenID::Integer;

is(Protocol::OpenID::Integer->new(),      "");
is(Protocol::OpenID::Integer->new(0),     "\x00");
is(Protocol::OpenID::Integer->new(127),   "\x7F");
is(Protocol::OpenID::Integer->new(128),   "\x00\x80");
is(Protocol::OpenID::Integer->new(255),   "\x00\xFF");
is(Protocol::OpenID::Integer->new(32768), "\x00\x80\x00");
is(Protocol::OpenID::Integer->new(-1),    "");
is(Protocol::OpenID::Integer->new('foo'), "");

is(Protocol::OpenID::Integer->new->parse("\x00"),         (0));
is(Protocol::OpenID::Integer->new->parse("\x7F"),         (127));
is(Protocol::OpenID::Integer->new->parse("\x00\x80"),     (128));
is(Protocol::OpenID::Integer->new->parse("\x00\xFF"),     (255));
is(Protocol::OpenID::Integer->new->parse("\x00\x80\x00"), (32768));
