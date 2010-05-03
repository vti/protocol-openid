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
        $tx->state('discovery_yadis_start');
        Protocol::OpenID::Discoverer::Yadis->discover(
            $http_req_cb,
            $tx => sub {
                my $tx = shift;

                unless ($tx->error) {
                    $tx->state('discovery_yadis_done');
                    return $cb->($tx);
                }

                $tx->error(undef);

                $tx->state('discovery_html_start');
                Protocol::OpenID::Discoverer::HTML->discover(
                    $http_req_cb,
                    $tx => sub {
                        my $tx = shift;

                        $tx->state('discovery_html_done') unless $tx->error;

                        return $cb->($tx);
                    }
                );
            }
        );
    }
    else {
        $tx->state('discovery_html_start');
        Protocol::OpenID::Discoverer::HTML->discover(
            $http_req_cb,
            $tx => sub {
                my $tx = shift;

                $tx->state('discovery_html_done') unless $tx->error;

                return $cb->($tx);
            }
        );
    }
}

1;
