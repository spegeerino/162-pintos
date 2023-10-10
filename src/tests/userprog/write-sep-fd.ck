# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(write-sep-fd) begin
(write-sep-fd) create "test.txt"
(write-sep-fd) create "test2.txt"
(write-sep-fd) open "test.txt" first time
(write-sep-fd) open "test.txt" second time
(write-sep-fd) open "test2.txt" first time
(write-sep-fd) open "test2.txt" second time
(write-sep-fd) end
write-sep-fd: exit(0)
EOF
pass;

