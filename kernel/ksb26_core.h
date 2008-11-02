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

#define DEBUG 1 

#define KSB26_S4HSOK(buf) do { if(buf[1] != 0x5A) { kfree(buf); return -1; } } while(0)
#define KSB26_S5HSOK(buf) do { if(buf[0] != 0x05 || buf[1] != 0x00) { kfree(buf); return -1; } } while(0)
#define KSB26_SOCKS5HS "\x05\x01%c"
#define KSB26_SOCKS5RQ "\x05\x01%c\x03%c%s%c%c"
#define KSB26_DOWN_LISTSEM do { down_interruptible(&ksb26_cntsem); ksb26_connect_cnt++; \
    if(ksb26_connect_cnt == 1) down_interruptible(&ksb26_listsem); up(&ksb26_cntsem); } while(0)
#define KSB26_UP_LISTSEM do { down_interruptible(&ksb26_cntsem); ksb26_connect_cnt--; \
    if(ksb26_connect_cnt == 0) up(&ksb26_listsem); up(&ksb26_cntsem); } while(0)

static long ksb26_sendto(struct socket *sock, void *buff, int len, int flags)
{
    struct msghdr msg;
    struct iovec iov;

    if (!sock)
        return -1;
    iov.iov_base = buff;
    iov.iov_len = len;
    msg.msg_name = NULL;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_namelen = 0;
    msg.msg_flags = flags;
    if (sock->file->f_flags & O_NONBLOCK)
        flags |= MSG_DONTWAIT;
    return sock_sendmsg(sock, &msg, len);
}

static long ksb26_recvfrom(struct socket *sock, char *buff, int bufflen, int flags)
{
    struct iovec iov;
    struct msghdr msg;

    if(!sock)
        return -1;
    msg.msg_control=NULL;
    msg.msg_controllen=0;
    msg.msg_iovlen=1;
    msg.msg_iov=&iov;
    iov.iov_len=bufflen;
    iov.iov_base=buff;
    return sock_recvmsg(sock, &msg, bufflen, flags);
}


static int ksb26_2bounce(unsigned long naddr, unsigned short nport)
{
    struct ksb26_host *ksb26_bhlaux = ksb26_bhlh.next;

    for(; ksb26_bhlaux != &ksb26_bhlh; ksb26_bhlaux = ksb26_bhlaux->next) {
        if(ksb26_bhlaux->naddr == naddr || ksb26_bhlaux->ip[0] == '*') { 
            if((ksb26_bhlaux->port == ntohs(nport) || ksb26_bhlaux->port == 0) && ntohs(nport) != 53) {
                return 1;
            }
        }
    }
    return 0;
}

static int ksb26_socks5hs(struct socket *sock, char *dhost, int dport)
{
    int buflen = 0;
    char *buf = NULL;
    int err= -1;
    mm_segment_t oldfs;

    buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
    buflen = snprintf(buf, PAGE_SIZE, KSB26_SOCKS5HS, 0);
    oldfs = get_fs();
    set_fs(get_ds());
    err = ksb26_sendto(sock, buf, buflen, 0);
    ksb26_recvfrom(sock, buf, PAGE_SIZE, 0);
    KSB26_S5HSOK(buf);
    buflen = snprintf(buf, PAGE_SIZE, KSB26_SOCKS5RQ, 0, strlen(dhost), dhost, (dport >> 8) & 0xFF, dport & 0xFF);
    ksb26_sendto(sock, buf, buflen, 0);
    ksb26_recvfrom(sock, buf, PAGE_SIZE, 0);
    set_fs(oldfs);
    KSB26_S5HSOK(buf);
    kfree(buf);
    return 1;
}

static int ksb26_1st_socks(struct socket *sock, struct sockaddr **uaddr, int addr_len, struct ksb26_host **ksb26_slaux, int flags)
{
    struct sockaddr_in *ksin = (struct sockaddr_in *)*uaddr;
    int err = -1;
    mm_segment_t oldfs;
    struct ksb26_host *ksb26_aux;

    printk("FIRST SOCKS\n");
    for(ksb26_aux = ksb26_slh.next; ksb26_aux != &ksb26_slh && err != 0; ksb26_aux = ksb26_aux->next) {
        printk("[%s] [1st socks] Trying %s:%d SOCKS5.\n", MODNAME, ksb26_aux->ip, ksb26_aux->port);
        if(ksb26_aux->wrk == 1) {
#ifdef DEBUG
            printk("[%s] Trying [1] %s:%d SOCKS5.\n", MODNAME, ksb26_aux->ip, ksb26_aux->port);
#endif
            oldfs = get_fs();
            set_fs(get_ds());
            ksin->sin_addr.s_addr = ksb26_aux->naddr;
            ksin->sin_port = ksb26_aux->nport;
            set_fs(oldfs);
            err = orig_unix_stream_connect(sock, *uaddr, addr_len, flags);
        }
    }
    if(err == 0) {
        *ksb26_slaux = ksb26_aux->prev;
        printk("[%s] Connected to %s:%d [1] SOCKS5.\n", MODNAME, ksb26_aux->prev->ip, ksb26_aux->prev->port);
    }
    return err;
}

static int ksb26_socks_chain(struct socket *sock, int *scnt, struct ksb26_host **ksb26_slaux)
{
    struct ksb26_host *ksb26_aux = *ksb26_slaux;
    int err = 1;
    for(*scnt = 1, ksb26_aux = ksb26_aux->next; ksb26_aux != &ksb26_slh && *scnt < ksb26_maxsocks ; ksb26_aux = ksb26_aux->next) {
        if(ksb26_aux->wrk == 1) {
#ifdef DEBUG
            printk("[%s] Trying [%d] %s:%d SOCKS5.\n", MODNAME, (*scnt) + 1, ksb26_aux->ip, ksb26_aux->port);
#endif
            if((err = ksb26_socks5hs(sock, ksb26_aux->ip, ksb26_aux->port)) > 0) {
                (*scnt)++;
                printk("[%s] Connected to %s:%d [%d] SOCKS v5.\n", MODNAME, ksb26_aux->ip, ksb26_aux->port, *scnt);
            } else 
                break;

        }
    }
    *ksb26_slaux = ksb26_aux->prev;
    return err;
}

static int ksb26_unix_stream_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags)
{
    mm_segment_t oldfs;
    struct sockaddr_in *ksin = (struct sockaddr_in *)uaddr;
    struct ksb26_host *ksb26_slaux;
    unsigned long int daddr = 0;
    unsigned short int dport = 0;
    int err = 0, scnt = 1;

    KSB26_DOWN_LISTSEM;	
    oldfs = get_fs();
    set_fs(get_ds());
    if (ksb26_2bounce(ksin->sin_addr.s_addr, ksin->sin_port) == 1) {
#ifdef DEBUG
        printk("[%s] SYS_CONNECT_KSB26 : localhost -> %s:%d\n", MODNAME, ksb26_ntoa(ksin->sin_addr.s_addr), ntohs(ksin->sin_port));
#endif
        daddr = ksin->sin_addr.s_addr;
        dport = ksin->sin_port;
        set_fs(oldfs);

        if((err = ksb26_1st_socks(sock, &uaddr, addr_len, &ksb26_slaux, 2)) != 0) {
            KSB26_UP_LISTSEM;
            return err;
        }
        if(ksb26_socks_chain(sock, &scnt, &ksb26_slaux) <= 0) {	
            //			ksb26_slaux->wrk = 0;
            KSB26_UP_LISTSEM;
            printk("[%s] Please retry.\n", MODNAME);
            return -1;
        }

        if(scnt < ksb26_maxsocks) {
            KSB26_UP_LISTSEM;
            printk("[%s] Too few working SOCKS in list.\n", MODNAME);
            return err;
        }
        
        err = ksb26_socks5hs(sock, ksb26_ntoa(daddr), ntohs(dport));
        if(err <= 0) {
            //			ksb26_slaux->wrk = 0;
            KSB26_UP_LISTSEM;
            printk("[%s] Connection refused to destination host [%s:%d].\n", MODNAME, ksb26_ntoa(daddr), ntohs(dport));
            return -ECONNREFUSED;
        }
        printk("[%s] Connected to destination host [%s:%d].\n", MODNAME, ksb26_ntoa(daddr), ntohs(dport));
    } else  {
        set_fs(oldfs);
        err = orig_unix_stream_connect(sock, uaddr, addr_len, flags);
    }
    KSB26_UP_LISTSEM;
    return err;
}

