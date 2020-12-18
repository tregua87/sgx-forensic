#!/bin/bash
make clean
make
sudo zip $(lsb_release -i -s)_$(uname -r)_profile.zip ./module.dwarf /boot/System.map-$(uname -r)