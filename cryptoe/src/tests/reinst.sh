#!/bin/sh
PROJ_ROOT="$HOME/storage/projects/cryptoe"
LIB_ROOTS="/opt/cryptoe /b/dive/venv $HOME/.local"
VENVS="/opt/cryptoe/venv /b/dive/venv/dilligaf-py27"

cd ${PROJ_ROOT}/cryptoe

clean_inst()
{
    python setup.py clean --all
    python setup.py build
    python setup.py install
}

cleanup()
{
    # This is just to ensure that the new library is the only one around.
    # It's only useful when I'm messing with setup.py and have broken something :)
    find ${LIB_ROOTS} -type f -name cryptoe_ext.so -exec rm -f {} \;
    cd ~/storage/projects/cryptoe/cryptoe
    clean_inst
}

for v in ${VENVS}
do
    (. ${v}/bin/activate && clean_inst)
done
python setup.py clean --all install --user --force

