package Protocol::OpenID::Discovery::Yadis;

use Protocol::Yadis;
use Protocol::OpenID::Discovery;

sub hook {
    my ($ctl, $args)       = @_;
    my ($rp,  $identifier) = @$args;

    # Create Yadis Protocol object passing the same http_req_cb
    # callback that we got from the higher level
    my $y = Protocol::Yadis->new(http_req_cb => $rp->http_req_cb);

    my $url = $identifier->to_string;

    $y->discover(
        $url,
        sub {
            my ($y, $rv) = @_;

            # Yadis document was found
            if ($rv eq 'ok') {
                my $document = $y->document;

                # Convert Yadis Document to OpenID Discovered Info

                # Find OpenID services
                my @openid_services =
                  grep { $_->Type->[0]->content =~ m/specs\.openid\.net/ }
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

                        last;
                    }
                }

                $rp->discovery($discovery);

                $ctl->done;
            }

            # No Yadis Document was found, thus call the next hook
            else {

                $rp->error($y->error);

                $ctl->next;
            }
        }
    );
}

1;
