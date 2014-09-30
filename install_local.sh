#!/bin/sh
sudo pip2 install -r requirements.txt

echo "================================================"
echo "Now please put this directory in your PYTHONPATH"
echo "and the bin directory in your PATH."
echo
echo "If you are using bash, you do can this by putting"
echo "These in your .bashrc:"
echo
echo "export PATH=\"`realpath bin`:\$PATH\""
echo "export PYTHONPATH=\"`realpath .`:\$PYTHONPATH\""
