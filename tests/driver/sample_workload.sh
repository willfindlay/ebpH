#! /bin/bash

# ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
# Copyright (C) 2019-2020  William Findlay
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# A sample workload for unit tests.
#
# 2020-Jul-13  William Findlay  Created this.

ls | wc -l
ps aux
ls > /tmp/ls.log
cat /tmp/ls.log
/bin/echo foo > /tmp/foo
grep foo /tmp/foo
