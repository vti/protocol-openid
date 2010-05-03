package Protocol::OpenID::Discoverer;

use strict;
use warnings;

use Protocol::OpenID::Discoverer::HTML;

# Yadis discovery requires Protocol::Yadis
use constant HAVE_YADIS => eval { require Protocol::OpenID::Discoverer::Yadis; 1 };

sub discover {
    my $class = shift;
    my ($http_req_cb, $tx, $cb) = @_;

    if (HAVE_YADIS) {
        Protocol::OpenID::Discoverer::Yadis->discover(
            $http_req_cb,
            $tx => sub {
                my $tx = shift;

                return $cb->($tx) unless $tx->error;

                $tx->error(undef);

                Protocol::OpenID::Discoverer::HTML->discover(
                    $http_req_cb,
                    $tx => sub {
                        my $tx = shift;

                        return $cb->($tx);
                    }
                );
            }
        );
    }
    else {
        Protocol::OpenID::Discoverer::HTML->discover(
            $http_req_cb,
            $tx => sub {
                my $tx = shift;

                return $cb->($tx);
            }
        );
    }
}

1;
