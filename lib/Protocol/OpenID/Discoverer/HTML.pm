package Protocol::OpenID::Discoverer::HTML;

use strict;
use warnings;

use base 'Protocol::OpenID::Discoverer::Base';

use constant DEBUG => $ENV{PROTOCOL_OPENID_DEBUG} || 0;

use Protocol::OpenID::Discovery;

sub discover {
    my $self = shift;
    my ($identifier, $cb) = @_;

    $self->error('');

    my $url = $identifier->to_string;
    warn "Discovering HTML Document at '$url'" if DEBUG;

    $self->http_req_cb->(
        $url => 'GET' => {Accept => '*/*'} => '' => sub {
            my ($url, $status, $headers, $body) = @_;

            my $discovery =
              $self->_http_res_on($url, $status, $headers, $body);

            return $cb->($self, $discovery) if !$self->error && $discovery;

            # Nothing was discovered in HTML
            return $cb->($self);
        }
    );
}

sub _http_res_on {
    my ($self, $url, $status, $headers, $body) = @_;

    unless ($status && $status == 200) {
        $self->error("Wrong response status: $status");
        return;
    }

    unless ($body) {
        $self->error('No body');
        return;
    }

    my ($head) = ($body =~ m/<\s*head\s*>(.*?)<\/\s*head\s*>/is);
    unless ($head) {
        $self->error('No <head>');
        return;
    }

    my $links = _html_links(\$head);

    my ($version, $provider, $local_id);

    if ($provider = $links->{'openid2.provider'}) {
        $version = $Protocol::OpenID::Discovery::VERSION_2_0;
        $local_id = $links->{'openid2.local_id'};
    }
    elsif ($provider = $links->{'openid.server'}) {
        $version  = $Protocol::OpenID::Discovery::VERSION_1_1;
        $local_id = $links->{'openid.delegate'};
    }

    # openid2.provider is required
    unless ($provider) {
        $self->error('No provider found');
        return;
    }

    my $discovery = Protocol::OpenID::Discovery->new(
        op_endpoint         => $provider,
        claimed_identifier  => $url,
        op_local_identifier => $local_id || $url,
        protocol_version    => $version
    );

    return $discovery;
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
