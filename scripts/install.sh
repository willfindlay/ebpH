#! /usr/bin/env -S bash -e

DIR=$(dirname $(readlink -f $0))/..
INSTALLDIR=/opt/ebpH

cd $DIR
sudo chown root:root ebpH_command && sudo chmod 700 ebpH_command

sudo mkdir -p $INSTALLDIR
sudo cp -r ./* $INSTALLDIR

cd $INSTALLDIR
sudo ln -sf $(readlink -f ./ebpH) /bin/ebpH
