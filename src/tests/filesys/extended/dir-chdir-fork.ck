# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(dir-chdir-fork) mkdir "a"
(dir-chdir-fork) create "a/b"
(dir-chdir-fork) chdir "a"
(child-chdir) open "../b"
(dir-chdir-fork) open "b"
EOF
pass;