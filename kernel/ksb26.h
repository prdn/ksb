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

#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/in.h>
#include <asm/semaphore.h>
#include <linux/byteorder/generic.h>
#include <net/sock.h>
#include <linux/aio.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/preempt.h>
#include <linux/un.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <net/af_unix.h>
#include <linux/net.h>

#define MODNAME "ksb26"
#define KSB26_VERSION "0.0.1"

#define KSB26_DEV_NAME "ksb26"
#define KSB26_IOCTL_BUFLEN 4096
#define KSB26_MAXSOCKS 1

#define KSB26_INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while(0)
#define KSB26_CLEAR_HSTRUCT(ksb26_hs) do { \
	memset(ksb26_hs.ip, '\0', 18); \
	memset(ksb26_hs.ipc, '\0', 4); \
	ksb26_hs.port = 0; \
	ksb26_hs.naddr = 0; \
	ksb26_hs.nport = 0; \
	ksb26_hs.wrk = 0; } while(0)

#define DEBUG 1

unsigned int ksb26_nsocks;
unsigned int ksb26_nbhddrs;
struct ksb26_host ksb26_slh;
struct ksb26_host ksb26_bhlh;
struct semaphore ksb26_listsem;
struct semaphore ksb26_cntsem;
int ksb26_connect_cnt; 
int ksb26_maxsocks;

static int nsocks = KSB26_MAXSOCKS;
static int ksb26_major;
static char ksb26_ioctl_msg[KSB26_IOCTL_BUFLEN];
static int ksb26_dev_bool = 0;

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);


static struct file_operations fops = {
	.write = device_write,
	.open = device_open,
	.release = device_release
};

struct ksb26_host {
	unsigned long naddr;
	unsigned short nport;
	char ip[18];
	char ipc[5];
	int port;
	int wrk;
	struct ksb26_host *next;
	struct ksb26_host *prev;
};

static struct proto_ops *unix_stream_ops = NULL;
static int (*orig_unix_stream_connect)(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags) = NULL;
static int ksb26_unix_stream_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);
asmlinkage long sys_send(int fd, void __user * buff, size_t len, unsigned flags);

#include "ksb26_misc.h"
#include "ksb26_list.h"
#include "ksb26_core.h"

