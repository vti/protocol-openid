package Protocol::OpenID::Discoverer::Yadis;

use strict;
use warnings;

use base 'Protocol::OpenID::Discoverer::Base';

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::Yadis;
use Protocol::OpenID;
use Protocol::OpenID::Discovery;

sub discover {
    my $self = shift;
    my ($identifier, $cb) = @_;

    $self->error('');

    # Create Yadis Protocol object passing the same http_req_cb
    # callback that we got from the higher level
    my $y = Protocol::Yadis->new(http_req_cb => $self->http_req_cb);

    my $url = $identifier->to_string;
    warn "Discovering Yadis Document at '$url'" if DEBUG;

    $y->discover(
        $url,
        sub {
            my ($y, $document) = @_;

            # Yadis document was found
            if ($document) {

                # Convert Yadis Document to OpenID Discovered Info

                warn 'Yadis Document was found' if DEBUG;

                # Find OpenID services
                my @openid_services =
                  grep { $_->Type->[0]->content =~ m/openid\.net/ }
                  @{$document->services};

                my $discovery;
                foreach my $service (@openid_services) {
                    my $type = $service->Type->[0]->content;

                    # OP Identifier
                    if ($type eq 'http://specs.openid.net/auth/2.0/server') {
                        $discovery = Protocol::OpenID::Discovery->new(
                            op_endpoint   => $service->URI->[0]->content,
                            op_identifier => $url
                        );

                        warn 'Found OP Identifier' if DEBUG;
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

                        $discovery = Protocol::OpenID::Discovery->new(
                            op_endpoint        => $service->URI->[0]->content,
                            claimed_identifier => $url,
                            op_local_identifier => $op_local_identifier
                        );

                        warn 'Found OP Local Identifier' if DEBUG;
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

                        $discovery = Protocol::OpenID::Discovery->new(
                            op_endpoint        => $service->URI->[0]->content,
                            claimed_identifier => $url,
                            op_local_identifier => $op_local_identifier,
                            ns                  => $1 == 1
                            ? OPENID_VERSION_1_1
                            : OPENID_VERSION_1_0
                        );

                        warn "Found OpenID 1.$1 Identifier" if DEBUG;
                        last;
                    }
                }

                if ($discovery) {
                    warn 'Found Discovery Information' if DEBUG;

                    $cb->($self, $discovery);
                }
                else {
                    $self->error('No services were found');

                    $cb->($self);
                }
            }

            # No Yadis Document was found
            else {
                $self->error($y->error);

                $cb->($self);
            }
        }
    );
}

1;
