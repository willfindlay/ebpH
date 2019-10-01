#! /usr/bin/env bash

DIR=$(dirname $(readlink -f $0))/..
INSTALLDIR=/opt/ebpH

cd $DIR
mkdir -p $INSTALLDIR

# make sure root owns /opt/ebpH
chown root:root $INSTALLDIR

# copy everything into /opt/ebpH
cp -r ./* $INSTALLDIR

cp ./scripts/ebphd.service /etc/systemd/system/ebphd.service

# navigate to /opt/ebpH
cd $INSTALLDIR

# create the symbolic link for ebphd
ln -sf $(readlink -f ./ebphd) /bin/ebphd
