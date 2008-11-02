/*****************************************************************************/
/* Kernel SOCKS Bouncer (Loadable Kernel Module) for 2.6.x kernels [KSB26]   */
/* (c) 2004-2008 Paolo Ardoino <paolo.ardoino@gmail.com>                     */
/*****************************************************************************/
/*									     */
/* This program is free software; you can redistribute it and/or modify	     */
/* it under the terms of the GNU General Public License as published by	     */
/* the Free Software Foundation; either version 2 of the License, or	     */
/* (at your option) any later version.					     */
/* This program is distributed in the hope that it will be useful,	     */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of	     */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	     */
/* GNU General Public License for more details.				     */
/*									     */
/* You should have received a copy of the GNU General Public License	     */
/* along with this program; if not, write to the Free Software		     */
/* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */
/*****************************************************************************/

#include "ksb26.h"

static int unpatch_unix_stream_connect(void)
{
	if (unix_stream_ops && orig_unix_stream_connect) {
		unix_stream_ops->connect = orig_unix_stream_connect;
		return 0;
	}
	return -1;
}

static int patch_unix_stream_connect(void)
{
	struct socket *sock_stream = NULL;

	if (sock_create(2, 1, 0, &sock_stream) < 0)
		return -1;
        if (sock_stream && (unix_stream_ops = sock_stream->ops)) {
		orig_unix_stream_connect = unix_stream_ops->connect;
		unix_stream_ops->connect = ksb26_unix_stream_connect;
		sock_release(sock_stream);
	}
	return 0;
}

static int device_open(struct inode *inode, struct file *file)
{
	if(ksb26_dev_bool == 1) 
		return -EBUSY;	
	ksb26_dev_bool++;
	try_module_get(THIS_MODULE);
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	ksb26_dev_bool--;
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t device_write(struct file *filp, const char *buffer, size_t lenght, loff_t *offset)
{
	int bytes_write = 0, linelen = 0;
	char *aux, *line;
	
	for(bytes_write = 0; bytes_write < lenght && bytes_write < KSB26_IOCTL_BUFLEN; bytes_write++)
		get_user(ksb26_ioctl_msg[bytes_write], buffer + bytes_write);
	ksb26_ioctl_msg[lenght - 1] = '\0';
	aux = ksb26_ioctl_msg;
	down_interruptible(&ksb26_listsem);
	while(aux < ksb26_ioctl_msg + lenght) {
		if((linelen = ksb26_getline(aux, -1, '\n', &line)) == 0) {
			up(&ksb26_listsem);
			return bytes_write;
		}
                printk("%s\n", line);
		if(line[0] == 'S')
			if(ksb26_add_socks(line) == 0)
				printk("[%s] Warning: failed to add SOCKS in '%s' line.\n", MODNAME, line);
		if(line[0] == 'H')
			if(ksb26_add_thost(line) == 0)
				printk("[%s] Warning: failed to add host in '%s' line.\n", MODNAME, line);
		if(line[0] == 'C') {
			ksb26_clear();
			printk("[%s] SOCKS list cleaned.\n", MODNAME);
		}
		aux = aux + linelen + 1;
		kfree(line);
	}
	up(&ksb26_listsem);
	return bytes_write;
}

static int __init modinit(void)
{
	printk("[%s v%s] MODULE LOADED\n", MODNAME, KSB26_VERSION);
	if((ksb26_major = register_chrdev(0, KSB26_DEV_NAME, &fops)) < 0) {
		printk("[%s] Cannot open device %s with %d major.\n", MODNAME, KSB26_DEV_NAME, ksb26_major);
		return -ENODEV;
	}
	printk("[%s] Device %s opened.\n", MODNAME, KSB26_DEV_NAME);
	printk("[%s] Major device number = %d.\n", MODNAME, ksb26_major);
	printk("[%s] mknod %s c %d 0\n", MODNAME, KSB26_DEV_NAME, ksb26_major);
	KSB26_INIT_LIST_HEAD(&ksb26_slh);
	KSB26_CLEAR_HSTRUCT(ksb26_slh);
	KSB26_INIT_LIST_HEAD(&ksb26_bhlh);
	KSB26_CLEAR_HSTRUCT(ksb26_bhlh);
	ksb26_connect_cnt = 0;
	ksb26_nsocks = 0;
	sema_init(&ksb26_listsem, 1);
	sema_init(&ksb26_cntsem, 1);
	printk("[%s] Hijacking SYS_CONNECT syscall.\n", MODNAME);
	ksb26_maxsocks = nsocks;
	printk("[%s] ksb26_maxsocks = %d\n", MODNAME, ksb26_maxsocks);
	if(patch_unix_stream_connect() == -1) {
		printk("[%s] Warning: failed to patch unix_stream_connect.\n", MODNAME);
		return -1;
	}
	printk("[%s] unix_stream_connect patched successfully.\n", MODNAME);
	return 0;
}

static void __exit modcleanup(void)
{
	unregister_chrdev(ksb26_major, KSB26_DEV_NAME);
        printk("[%s] Cannot unregister device %s.\n", MODNAME, KSB26_DEV_NAME);
	
        if(unpatch_unix_stream_connect() == -1) {
		printk("[%s] Warning: failed to unpatch unix_stream_connect.\n", MODNAME);
		return;
	}
	printk("[%s] unix_stream_connect unpatched successfully.\n", MODNAME);
	printk("[%s] MODULE CLEANED\n", MODNAME);
	return;
}

module_init(modinit);
module_exit(modcleanup);

module_param(nsocks, int, 0);

MODULE_AUTHOR("Paolo Ardoino");
MODULE_DESCRIPTION("Kernel Socks Bouncer for 2.6.x kernels\n");
MODULE_LICENSE("GPL");
