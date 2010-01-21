package Protocol::OpenID::Authentication;

use strict;
use warnings;

use base 'Protocol::OpenID::Message';

sub assoc_handle { shift->param(assoc_handle => @_) }

1;
