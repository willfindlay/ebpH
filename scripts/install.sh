#! /usr/bin/env bash

PROJECTDIR=$(dirname $(readlink -f $0))/..
INSTALLDIR=/opt/ebpH

cd $PROJECTDIR
mkdir -p $INSTALLDIR

# make sure root owns /opt/ebpH
chown root:root $INSTALLDIR

# copy everything into /opt/ebpH
cp -r ./* $INSTALLDIR

# copy systemd unit file
# cp ./systemd/ebphd.service /etc/systemd/system/ebphd.service

# navigate to /opt/ebpH
cd $INSTALLDIR

# create the symbolic link for ebphd, ebph-ps, ebph-admin
ln -vsnf $(readlink -f ./ebphd) /bin/ebphd
ln -vsnf $(readlink -f ./ebph-ps) /bin/ebph-ps
ln -vsnf $(readlink -f ./ebph-admin) /bin/ebph-admin
ln -vsnf $(readlink -f ./ebph-inspect) /bin/ebph-inspect
