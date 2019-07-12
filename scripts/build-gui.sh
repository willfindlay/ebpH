#! /usr/bin/env -S bash -e

DIR=$(dirname $(readlink -f $0))/..
GUIDIR=$(dirname $(readlink -f $(find $DIR -name mainwindow.ui)))

# build the gui
cd $GUIDIR

# compile .ui files
for f in *.ui; do
    pyside2-uic --from-imports "$f" > "${f%.*}.py"
done

# compile .qrc files
for f in *.qrc; do
    pyside2-rcc "$f" > "${f%.*}_rc.py"
done
