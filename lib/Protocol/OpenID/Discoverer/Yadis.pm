package Protocol::OpenID::Discoverer::Yadis;

use strict;
use warnings;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::OpenID;
use Protocol::Yadis;

sub discover {
    my $class = shift;
    my ($http_req_cb, $tx, $cb) = @_;

    # Create Yadis Protocol object passing the same http_req_cb
    # callback that we got from the higher level
    my $y = Protocol::Yadis->new(http_req_cb => $http_req_cb);

    my $url = $tx->identifier;
    warn "Discovering Yadis Document at '$url'" if DEBUG;

    $y->discover(
        $url => sub {
            my ($y, $document) = @_;

            # Yadis document was found
            if ($document) {

                # Convert Yadis Document to OpenID Discovered Info

                warn 'Yadis Document was found' if DEBUG;

                # Find OpenID services
                my @openid_services =
                  grep { $_->Type->[0]->content =~ m/openid\.net/ }
                  @{$document->services};

                my $found;
                foreach my $service (@openid_services) {
                    my $type = $service->Type->[0]->content;

                    # OP Identifier
                    if ($type eq 'http://specs.openid.net/auth/2.0/server') {
                        $tx->op_endpoint($service->URI->[0]->content);
                        $tx->op_identifier($url);

                        warn 'Found OP Identifier' if DEBUG;
                        $found++;
                        last;
                    }

                    # Claimed Identifier
                    elsif ($type eq 'http://specs.openid.net/auth/2.0/signon')
                    {

                        # Optional OP Local Identifier
                        my $op_local_identifier = '';
                        if (my $local_id = $service->element('LocalID')->[0])
                        {
                            $op_local_identifier = $local_id->content;
                        }

                        $tx->op_endpoint($service->URI->[0]->content);
                        $tx->claimed_identifier($url);
                        $tx->op_local_identifier($op_local_identifier);

                        warn 'Found OP Local Identifier' if DEBUG;
                        $found++;
                        last;
                    }
                    elsif (
                        $type =~ m/^http:\/\/openid\.net\/signon\/1\.(0|1)$/)
                    {

                        # Optional OP Local Identifier
                        my $op_local_identifier = $url;
                        my $local_id = $service->element('openid:Delegate');
                        if ($local_id && $local_id->[0]) {
                            $op_local_identifier = $local_id->[0]->content;
                        }

                        $tx->ns(undef);
                        $tx->op_endpoint($service->URI->[0]->content);
                        $tx->claimed_identifier($url);
                        $tx->op_local_identifier($op_local_identifier);

                        warn "Found OpenID 1.$1 Identifier" if DEBUG;
                        $found++;
                        last;
                    }
                }

                if ($found) {
                    warn 'Found Discovery Information' if DEBUG;

                    $cb->($tx);
                }
                else {
                    $tx->error('No services were found');

                    $cb->($tx);
                }
            }

            # No Yadis Document was found
            else {
                $tx->error($y->error);

                $cb->($tx);
            }
        }
    );
}

1;
