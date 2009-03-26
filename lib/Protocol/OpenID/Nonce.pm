package Protocol::OpenID::Nonce;
use Mouse;

use overload '""' => sub { shift->to_string }, fallback => 1;

require Time::Local;

has epoch => (
    isa => 'Int',
    is  => 'rw'
);

has tail => (
    isa => 'Str',
    is  => 'rw'
);

sub new {
    my $self = shift->SUPER::new();
    $self->parse(@_);
    return $self;
}

sub parse {
    my $self = shift;
    my $date = shift;

    return unless defined $date;

    if ($date =~ /^\d+$/) {
        $self->epoch($date);
        return $self;
    }

    $date = substr($date, 0, 255);

    my ($day, $month, $year, $hour, $minute, $second, $tail);

    # 2005-05-15T17:11:51ZUNIQUE
    if ($date =~ /^(\d+)-(\d+)-(\d+)(?:T|t)(\d+):(\d+):(\d+)(?:Z|z)([[:graph:]]+)?$/) {
        $year   = $1;
        $month  = $2;
        $day    = $3;
        $hour   = $4;
        $minute = $5;
        $second = $6;
        $tail   = $7;
    }
    else {
        return undef;
    }

    my $epoch;

    # Prevent crash
    eval {
        $epoch =
          Time::Local::timegm($second, $minute, $hour, $day, $month - 1, $year);
    };

    return undef if $@;

    $self->epoch($epoch);
    $self->tail($tail) if $tail;

    return $self;
}

sub to_string {
    my $self = shift;
    my $epoch = shift || $self->epoch;

    $epoch = time unless defined $epoch;

    my ($second, $minute, $hour, $mday, $month, $year, $wday) = gmtime $epoch;

    my $string = sprintf(
        "%04d-%02d-%02dT%02d:%02d:%02dZ",
        $year + 1900,
        $month + 1, $mday, $hour, $minute, $second
    );

    $string .= $self->tail if $self->tail;

    $string = substr($string, 0, 255);

    return $string;
}

1;