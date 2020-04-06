#! /usr/bin/env sh

INSTALLDIR=/opt/ebpH
BINDIR=/usr/bin

# Find root of project
PROJECTDIR=$(dirname $(readlink -f $0))/..

setup_install_dir()
(
    # Remove and remake $INSTALLDIR
    rm -rf "$INSTALLDIR"
    mkdir -p "$INSTALLDIR"
    # Copy everything into /opt/ebpH
    cp -r "$PROJECTDIR" "$INSTALLDIR"
    # Make sure root owns /opt/ebpH and its children
    chown -R root:root "$INSTALLDIR"
    # Install python  package
	pip3 install -e "$INSTALLDIR"
)

install()
(
    setup_install_dir
    # Create symlinks
    for filename in $INSTALLDIR/bin/*; do
        [ -f "$filename" ] || continue
        ln -vsnf "$filename" "$BINDIR/$(basename $filename)"
    done
)

install
