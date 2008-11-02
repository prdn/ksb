echo "Kernel SOCKS Bouncer for 2.6.x kernels"
make -C /usr/src/linux/ SUBDIRS=$PWD V=1 modules
rm *.o *.mod.c .*.cmd
rm -r .tmp_versions
