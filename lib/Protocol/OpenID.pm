package Protocol::OpenID;

use strict;
use warnings;

our $VERSION = '0.000101';

use constant OPENID_VERSION_1_0 => 'http://openid.net/signon/1.0';
use constant OPENID_VERSION_1_1 => 'http://openid.net/signon/1.1';
use constant OPENID_VERSION_2_0 => 'http://specs.openid.net/auth/2.0';

use constant OPENID_IDENTIFIER_SELECT =>
  'http://specs.openid.net/auth/2.0/identifier_select';

use Exporter qw(import);
our @EXPORT = qw/
  OPENID_VERSION_1_0
  OPENID_VERSION_1_1
  OPENID_VERSION_2_0
  OPENID_IDENTIFIER_SELECT
  /;

1;
