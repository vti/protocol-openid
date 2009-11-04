#!/usr/bin/env perl

use 5.008001;

use strict;
use warnings;

use ExtUtils::MakeMaker;

my $mm = $ExtUtils::MakeMaker::VERSION;

WriteMakefile(
    NAME         => 'Protocol::OpenID',
    VERSION_FROM => 'lib/Protocol/OpenID.pm',
    ABSTRACT     => 'OpenID implementation',
    AUTHOR       => 'Viacheslav Tykhanovskyi <vti@cpan.org>',

    ($mm < 6.3002 ? () : ('LICENSE' => 'artistic_2')),

    (   $mm < 6.46
        ? ()
        : ( META_MERGE => {
                requires  => {perl => '5.008001'},
                resources => {
                    homepage => 'http://github.com/vti/protocol-openid',
                    license  => 'http://dev.perl.org/licenses/',
                    repository =>
                      'http://github.com/vti/protocol-openid/tree/master'
                },
                no_index => {directory => [qw/t/]}
            },
            META_ADD => {
                build_requires     => {},
                configure_requires => {}
            },
        )
    ),

    PREREQ_PM => {
        'Math::BigInt'    => 0,
        'Protocol::Yadis' => 0,
        'Time::Local'     => 0,
    },
    test => {TESTS => 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t'}
);
