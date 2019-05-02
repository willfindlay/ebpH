/* ebpH --  Monitor syscall sequences and detect anomalies
 * Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
 * William Findlay (williamfindlay@cmail.carleton.ca)
 *
 * Based on Sasha Goldshtein's syscount
 *  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
 *  Copyright 2017, Sasha Goldshtein.
 * And on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
 *
 * USAGE: ebpH.py <COMMAND>
 *
 * Licensed under MIT License */

// TODO: change this to load profile
static pH_seq load_sequence()
{
    ARG_PROFILE
    return s;
}
