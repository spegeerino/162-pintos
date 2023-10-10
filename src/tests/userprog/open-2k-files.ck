# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(open-2k-files) begin
(open-2k-files) create "test.txt"
(open-2k-files) end
open-2k-files: exit(0)
EOF
pass;
