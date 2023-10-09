# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-wrong-pid) begin
(child-simple) run
child-simple: exit(81)
(wait-wrong-pid) wait(exec()) = -1
(wait-wrong-pid) wait(exec()) = 81
(wait-wrong-pid) end
wait-wrong-pid: exit(0)
EOF
pass;
