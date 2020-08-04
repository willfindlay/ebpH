/*  ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
 *  ebpH Copyright (C) 2019-2020  William Findlay
 *  pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        char *arg_list[] = {"ls", "-lah", NULL};
        execvp(arg_list[0], arg_list);
        printf("Failed with %s\n", strerror(errno));
    }

    write(1, "Hello, world!\n", 14);
}
