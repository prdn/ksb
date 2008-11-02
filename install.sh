#***************************************************************************#
# Kernel SOCKS Bouncer (install.sh) for 2.6.x kernels [ksb26]               #
# (c) 2004-2005 Paolo Ardoino <ardoino.gnu@disi.unige.it>                   #
#***************************************************************************#
#									    #
# This program is free software; you can redistribute it and/or modify	    #
# it under the terms of the GNU General Public License as published by	    # 
# the Free Software Foundation; either version 2 of the License, or	    # 
# (at your option) any later version.					    #
# This program is distributed in the hope that it will be useful,	    #
# but WITHOUT ANY WARRANTY; without even the implied warranty of	    #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.				    #
#									    #
# You should have received a copy of the GNU General Public License	    #
# along with this program; if not, write to the Free Software		    #
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA #
#***************************************************************************#


installer_version=0.0.2
kernel_dir=/usr/src/linux
bin_dir=/usr/bin

echo "Kernel Socks Bouncer for 2.6.x kernels Installer v$installer_version"
echo ""

# Checking all components of ksb26
echo "Checking components of ksb26:"
if [ ! -d kernel ] || [ ! user ] ; then
	echo "Cannot find subdirectoryes containing components of ksb26"
	exit -1
fi
echo -n "kernel/ksb26.c -> "
if [ ! -e kernel/ksb26.c ] ; then
	echo "not found!"
	exit -1
else
	echo "found!"
fi
echo -n "user/ksb26manager.c -> "
if [ ! -e user/ksb26manager.c ] ; then
	echo "not found!"
	exit -1
else
	echo "found!"
fi

# Checking Linux kernel source directory
if [ ! -d $kernel_dir ] || [ ! $kernel_dir/net ] || [ ! $kernel_dir/include ]  || [ ! $kernel_dir/kernel ] ; then
	echo "Cannot find Linux Kernel source in $kernel_dir"
	echo "Please edit this script and set 'kernel_dir' to the correct value'"
	exit -1
fi

# Starting installation
echo "Building kernel/ksb26.c"
make -C $kernel_dir/ SUBDIRS=$PWD/kernel V=1 modules
if [ ! -e kernel/ksb26.ko ] ; then
	exit -1
fi
echo "Building user/ksb26manager.c"
make -C user/
if [ ! -e user/ksb26manager ] ; then
	exit -1
fi
echo "Installing kernel/ksb26.ko"
make -C $kernel_dir/ SUBDIRS=$PWD/kernel V=1 modules_install
depmod
echo "Installing user/ksb26manager"
cp user/ksb26manager $bin_dir
if [ ! -e $bin_dir/ksb26manager ] ; then
	exit -1
fi
echo "Creating /etc/ksb26 directory"
mkdir /etc/ksb26
if [ ! -d /etc/ksb26 ] ; then
	exit -1
fi
echo "Installing configuration files"
cp thosts.example /etc/ksb26/
cp socks.example /etc/ksb26/
if [ ! -e /etc/ksb26/thosts.example ] ; then
	exit -1
fi
if [ ! -e /etc/ksb26/socks.example ] ; then
	exit -1
fi
echo "Installing man page (man 1 ksb26)"
cp ksb26.1.gz /usr/share/man/man1/
if [ ! -e /usr/share/man/man1/ksb26.1.gz ] ; then
	exit -1
fi
echo "Done"
echo ""
echo "Now you have to :"
echo "* read man page (man ksb26) for informations about the use of ksb26" 
echo "* set target hosts in /etc/ksb26/thosts"
