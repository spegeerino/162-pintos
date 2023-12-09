# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(dir-chdir-fork) begin
(dir-chdir-fork) mkdir "a"
(dir-chdir-fork) create "a/b"
(dir-chdir-fork) chdir "a"
(dir-chdir-fork) exec child 1 of 1: "../child-chdir 0"
((null)) see if "b" is inside directory
../child-chdir: exit(0)
(dir-chdir-fork) wait for child 1 of 1 returned 0 (expected 0)
(dir-chdir-fork) open "b"
(dir-chdir-fork) end
dir-chdir-fork: exit(0)
EOF
pass;