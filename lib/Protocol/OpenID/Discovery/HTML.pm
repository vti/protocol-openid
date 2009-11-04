package Protocol::OpenID::Discovery::HTML;

use strict;
use warnings;

use Protocol::OpenID::Discovery;

sub hook {
    my ($ctl, $args)       = @_;
    my ($rp,  $identifier) = @$args;

    my $url = $identifier->to_string;
    warn "Discovering HTML Document at '$url'" if $rp->debug;

    $rp->http_req_cb->(
        $rp => $url => {
            method  => 'GET',
            headers => {Accept => '*/*'}
          } => sub {
            my ($rp, $url, $status, $headers, $body) = @_;

            _http_res_on($rp, $url, $status, $headers, $body);
            return $ctl->done if !$rp->error && $rp->document;

            # Nothing was discovered in HTML, thus call the next hook
            $ctl->next;
        }
    );
}

sub _http_res_on {
    my ($rp, $url, $args) = @_;

    my $status  = $args->{status};
    my $headers = $args->{headers};
    my $body    = $args->{body};

    return $rp->error('Wrong response status') unless $status == 200;

    return $rp->error('No body') unless $body;

    my ($head) = ($body =~ m/<\s*head\s*>(.*?)<\/\s*head\s*>/is);
    return $rp->error('No <head>') unless $head;

    my $provider;
    my $local_id;

    my $version = $Protocol::OpenID::Discovery::VERSION_2_0;

    my $tags = _html_tag(\$head);
    foreach my $tag (@$tags) {
        next unless $tag->{name} eq 'link';

        my $attrs = $tag->{attrs};
        next unless %$attrs && $attrs->{'rel'};

        my @rels = split(' ', $attrs->{rel});

        foreach my $rel (@rels) {
            if ($rel eq 'openid2.provider' && !$provider) {
                $provider = $attrs->{href};
            }
            elsif ($rel eq 'openid2.local_id' && !$local_id) {
                $local_id = $attrs->{href};
            }
            elsif ($rel eq 'openid.server' && !$provider) {
                $provider = $attrs->{href};
                $version = $Protocol::OpenID::Discovery::VERSION_1_1;
            }
            elsif ($rel eq 'openid.delegate' && !$local_id) {
                $local_id = $attrs->{href};
                $version = $Protocol::OpenID::Discovery::VERSION_1_1;
            }
        }

        # No need to proceed if we have both
        last if $provider && $local_id;
    }

    # openid2.provider is required
    return $rp->error('No provider found') unless $provider;

    my $discovery = Protocol::OpenID::Discovery->new(
        op_endpoint         => $provider,
        claimed_identifier  => $url,
        op_local_identifier => $local_id || $url,
        protocol_version    => $version
    );
    $rp->discovery($discovery);

    return;
}

# based on HTML::TagParser
sub _html_tag {
    my $txtref = shift;    # reference
    my $flat   = [];

    # Strip comments
    $$txtref =~ s/<!--.*?-->//sg;

    # Strip scripts
    $$txtref =~ s/<script.*?>.*?<\/script>//isg;

    while (
        $$txtref =~ s{
        ^(?:[^<]*)
        < (?:
                ( / )?
                ( [^/!<>\s"'=]+ )
                ( (?:"[^"]*"|'[^']*'|[^"'<>])+ )?
            |
            (![^\-] .*? )
          ) \/?
        > ([^<]*)
    }{}sxg
      )
    {
        my $attrs;
        if ($3) {
            my $attr = $3;
            my $name;
            my $value;
            while ($attr =~ s/^([^=]+)=//s) {
                $name = lc $1;
                $name =~ s/^\s*//s;
                $name =~ s/\s*$//s;
                $attr =~ s/^\s*//s;
                if ($attr =~ m/^('|")/s) {
                    my $quote = $1;
                    $attr =~ s/^$quote(.*?)$quote//s;
                    $value = $1;
                }
                else {
                    $attr =~ s/^(.*?)\s*//s;
                    $value = $1;
                }
                $attrs->{$name} = $value;
            }
        }

        next if defined $4;
        my $hash = {
            name    => lc $2,
            content => $5,
            attrs   => $attrs
        };
        push(@$flat, $hash);
    }

    return $flat;
}

1;
