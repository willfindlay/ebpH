/*  ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
 *  Copyright (C) 2019-2020  William Findlay
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  A simple hello world program.
 *
 *  2020-Jul-16  William Findlay  Created this.
 */

#include <unistd.h>

int main(int argc, char **argv) {
    write(1, "Hello, world!\n", 14);

    if (argc > 1) {
        write(1, "Hello again, world!\n", 20);
    }
}
