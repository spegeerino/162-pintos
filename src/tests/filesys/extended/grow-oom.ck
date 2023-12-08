# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(grow-oom) begin
(grow-oom) create "testfile"
(grow-oom) open "testfile"
(grow-oom) seek "testfile"
(grow-oom) successfully failed to write "testfile"
(grow-oom) close "testfile"
(grow-oom) open "boondoggles" for verification
(grow-oom) open "boondoggles" for verification
(grow-oom) verified contents of "boondoggles"
(grow-oom) close "boondoggles"
(grow-oom) end
EOF
pass;