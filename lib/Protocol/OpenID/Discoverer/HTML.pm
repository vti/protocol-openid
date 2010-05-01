package Protocol::OpenID::Discoverer::HTML;

use strict;
use warnings;

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::OpenID;

my $URL_RE = qr{^https?://};

sub discover {
    my $class = shift;
    my ($http_req_cb, $tx, $cb) = @_;

    my $url = $tx->identifier;
    warn "Discovering HTML Document at '$url'" if DEBUG;

    $http_req_cb->(
        $url => 'GET' => {Accept => '*/*'} => '' => sub {
            _http_res_on($tx, @_);

            return $cb->($tx);
        }
    );
}

sub _http_res_on {
    my ($tx, $url, $status, $headers, $body, $error) = @_;

    if ($error) {
        $tx->error($error);
        return;
    }

    unless ($status && $status == 200) {
        $tx->error("Wrong $status response status");
        return;
    }

    unless ($body) {
        $tx->error('No body');
        return;
    }

    my ($head) = ($body =~ m/<\s*head\s*>(.*?)<\/\s*head\s*>/is);
    unless ($head) {
        $tx->error('No <head>');
        return;
    }

    my $links = _html_links(\$head);

    my ($provider, $local_id);

    # OpendId 2.0
    if ($provider = $links->{'openid2.provider'}) {
        $tx->ns(OPENID_VERSION_2_0);
        $local_id = $links->{'openid2.local_id'};
    }

    # OpenID 1.1
    elsif ($provider = $links->{'openid.server'}) {
        $tx->ns(undef);
        $local_id = $links->{'openid.delegate'};
    }

    # OpenID provider is required
    unless ($provider) {
        $tx->error('No provider found');
        return;
    }

    # URLs must be absolute
    unless ($provider =~ $URL_RE) {
        $tx->error('No provider found');
        return;
    }

    if ($local_id && $local_id !~ $URL_RE) {
        $local_id = undef;
    }

    $tx->op_endpoint($provider);
    $tx->claimed_identifier($url);
    $tx->op_local_identifier($local_id || $url);
}

sub _html_links {
    my $head = shift;

    my $links = {};

    my $tags = _html_tag($head);
    foreach my $tag (@$tags) {
        next unless $tag->{name} eq 'link';

        my $attrs = $tag->{attrs};
        next unless %$attrs && $attrs->{rel};
        next unless $attrs->{href};

        my @rels = split(' ', $attrs->{rel});

        $links->{$_} = $attrs->{href} for @rels;
    }

    return $links;
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
