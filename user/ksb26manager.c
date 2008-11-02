/*****************************************************************************/
/* Kernel SOCKS Bouncer Manager for 2.6.x kernels [KSB26]                    */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PNAME "ksb26manager"
#define VERSION "0.0.1"


#define PROC_DEV "/proc/devices"
#define DEFAULT_THOSTS "/etc/ksb26/thosts"
#define DEFAULT_SOCKS "/etc/ksb26/socks"
#define DEFAULT_LKM "ksb26"
#define DEFAULT_DEV "/dev/ksb26"
#define DEFAULT_WTIME 600
#define DEFAULT_NSOCKS 2
#define MAX_SOCKS 10

#define BUFFER_SIZE 1024
#define VARSIZE 128

int nsocks, wtime;
char ksb26_lkm[VARSIZE], ksb26_dev[VARSIZE];
char thosts[VARSIZE], socks[VARSIZE];

void help(void)
{
    printf("[%s] Usage: %s [-h] [-d ksb26_device] [-m ksb26_lkm_name]\n", PNAME, PNAME);
    printf("\t[-n nsocks] [-t thosts_file] [-w wait_time]\n\n");
    printf("\t[-d ksb26_device]: character device used by ksb26 [default:%s]\n", DEFAULT_DEV);
    printf("\t[-m ksb26_lkm_name]: lkm's name to use in modprobe command [default:%s]\n", DEFAULT_LKM);
    printf("\t[-n nsocks]: number of SOCKS used in chains [default:%d]\n", DEFAULT_NSOCKS);
    printf("\t[-t thosts_file]: file containing target hosts [default:%s]\n", DEFAULT_THOSTS);
    printf("\t[-s socks_file]: file containing default socks list [default:%s]\n", DEFAULT_SOCKS);
    printf("\t[-w wait_time]: number of seconds to wait before updating the SOCKS list [default:%d]\n", DEFAULT_WTIME);
    printf("\t[-h]: help\n");
    printf("Please read man page (man ksb26) or README to learn format of target hosts and SOCKS\n");
}

int get_major(char *name)
{
    FILE *fp;
    char tbuf[BUFFER_SIZE];
    int major = -1;

    if(!(fp = fopen(PROC_DEV, "r"))) {
        fprintf(stderr, "[%s] error: fopen: cannot find '%s' file\n", PNAME, PROC_DEV);
        return -1;
    }
    while(fgets(tbuf, BUFFER_SIZE, fp)) {
        if(strstr(tbuf, name))
            major = atoi(tbuf);
    }
    return major;
}

int insmod_ksb26(void)
{
    char cmd[BUFFER_SIZE];
    char buff[BUFFER_SIZE];
    FILE *fp;
    int major;

    snprintf(cmd, BUFFER_SIZE, "rmmod %s 1&> /dev/null", ksb26_lkm);
    system(cmd);
    printf("%s\n", cmd);
    snprintf(cmd, BUFFER_SIZE, "rm %s", ksb26_dev);
    system(cmd);
    printf("%s\n", cmd);
    snprintf(cmd, BUFFER_SIZE, "modprobe %s nsocks=%d", ksb26_lkm, nsocks);
    if(!(fp = popen(cmd, "r"))) {
        fprintf(stderr, "[%s] error: popen: failed popen(\"%s\", \"r\")\n", PNAME, cmd);
        return -1;
    }
    while(fgets(buff, BUFFER_SIZE, fp)) {
        if(strstr(buff, "FATAL") || strstr(buff, "fatal") || strstr(buff, "Fatal")) {
            fprintf(stderr, "[%s] error: modprobe: %s", PNAME, buff);
            pclose(fp);
            return -1;
        }
    }
    pclose(fp);
    if((major = get_major(ksb26_lkm)) < 0) {
        printf("[%s] error: cannot find '%s' major\n", PNAME, ksb26_lkm);
        return -1;
    }
    printf("major = %d\n", major);
    snprintf(cmd, BUFFER_SIZE, "mknod %s c %d 0", ksb26_dev, major);
    system(cmd);
    return 0;
}

int load_thosts_list(void)
{
    char cmd[BUFFER_SIZE];
    FILE *fp_dev, *fp_thosts;
    char buff[BUFFER_SIZE];

    if(!(fp_thosts = fopen(thosts, "r"))) {
        fprintf(stderr, "[%s] error: fopen: cannot find '%s' file\n", PNAME, thosts);
        return -1;
    }
    if(!(fp_dev = fopen(ksb26_dev, "w"))) {
        fprintf(stderr, "[%s] error: fopen: cannot open '%s' device\n", PNAME, ksb26_dev);
        fclose(fp_thosts);
        return -1;
    }
    while(fgets(buff, BUFFER_SIZE, fp_thosts)) {
        if(buff[0] != '#') {
            snprintf(cmd, BUFFER_SIZE, "%s\n", buff);
            fputs(cmd, fp_dev);
        }
    }
    fclose(fp_thosts);
    fclose(fp_dev);
    return 0;
}

int load_socks_list(void)
{
    char cmd[BUFFER_SIZE];
    FILE *fp_dev, *fp_socks;
    char buff[BUFFER_SIZE];

    if(!(fp_socks = fopen(socks, "r"))) {
        fprintf(stderr, "[%s] error: fopen: cannot find '%s' file\n", PNAME, socks);
        return -1;
    }
    if(!(fp_dev = fopen(ksb26_dev, "w"))) {
        fprintf(stderr, "[%s] error: fopen: cannot open '%s' device\n", PNAME, ksb26_dev);
        fclose(fp_socks);
        return -1;
    }
    while(fgets(buff, BUFFER_SIZE, fp_socks)) {
        if(buff[0] != '#') {
            snprintf(cmd, BUFFER_SIZE, "%s\n", buff);
            fputs(cmd, fp_dev);
        }
    }
    fclose(fp_socks);
    fclose(fp_dev);
    return 0;
}

int clear(void)
{
    char cmd[BUFFER_SIZE];
    FILE *fp_dev;
    char buff[BUFFER_SIZE];

    snprintf(cmd, BUFFER_SIZE, "C\n", ksb26_dev);
    if(!(fp_dev = fopen(ksb26_dev, "w"))) {
        fprintf(stderr, "[%s] error: fopen: cannot open '%s' device\n", PNAME, ksb26_dev);
        fclose(fp_dev);
        return -1;
    }
    fputs(cmd, fp_dev);
    fclose(fp_dev);
    return 0;
}

int main(int argc, char *argv[])
{
    int i;

    nsocks = DEFAULT_NSOCKS;
    wtime = DEFAULT_WTIME;
    strncpy(ksb26_lkm, DEFAULT_LKM, VARSIZE - 1);
    strncpy(ksb26_dev, DEFAULT_DEV, VARSIZE - 1);
    strncpy(thosts, DEFAULT_THOSTS, VARSIZE - 1);
    strncpy(socks, DEFAULT_SOCKS, VARSIZE - 1);
    printf("\n");
    printf("[%s] Kernel SOCKS Bouncer Manager v%s for ksb26\n", PNAME, VERSION);
    printf("[%s] by Paolo Ardoino <paolo.ardoino@gmail.com>\n\n", PNAME);
    for(i = 0; i < argc; i++) {
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            help();
            exit(EXIT_SUCCESS);
        }
    }
    for(i = 0; i < argc; i++) {
        if(strcmp(argv[i], "-n") == 0 && argv[i + 1]) {
            nsocks = atoi(argv[i + 1]);
            if(nsocks <= 0 || nsocks > 10) {
                fprintf(stderr, "[%s] error: nsocks: invalid value\n", PNAME);
                exit(EXIT_FAILURE);
            }
        }
        if((strcmp(argv[i], "-m") == 0) && argv[i + 1]) {
            memset(ksb26_lkm, '\0', VARSIZE);
            strncpy(ksb26_lkm, argv[i + 1], VARSIZE - 1);
        }
        if(strcmp(argv[i], "-t") == 0 && argv[i + 1]) {
            memset(thosts, '\0', VARSIZE);
            strncpy(thosts, argv[i + 1], VARSIZE - 1);
        }
        if(strcmp(argv[i], "-s") == 0 && argv[i + 1]) {
            memset(socks, '\0', VARSIZE);
            strncpy(socks, argv[i + 1], VARSIZE - 1);
        }
        if(strcmp(argv[i], "-d") == 0 && argv[i + 1]) {
            memset(ksb26_dev, '\0', VARSIZE);
            strncpy(ksb26_dev, argv[i + 1], VARSIZE - 1);
        }
        if(strcmp(argv[i], "-w") == 0 && argv[i + 1]) {
            wtime = atoi(argv[i + 1]);
            if(wtime <= 0) {
                fprintf(stderr, "[%s] error: wtime: invalid value\n", PNAME);
                exit(EXIT_FAILURE);
            }
        }
    }
    printf("[%s] modprobe %s nsocks=%d\n", PNAME, ksb26_lkm, nsocks);
    printf("[%s] ksb26 device: %s\n", PNAME, ksb26_dev);
    printf("[%s] thosts file: %s\n", PNAME, thosts);
    printf("[%s] socks file: %s\n", PNAME, socks);
    printf("[%s] wait time: %d\n", PNAME, wtime);

    if(insmod_ksb26() == -1) exit(EXIT_FAILURE);
    if(load_thosts_list() == -1) exit(EXIT_FAILURE);
    while(1) {
        if(clear() == -1) exit(EXIT_FAILURE);
        if(load_socks_list() == -1) exit(EXIT_FAILURE);
        sleep(wtime);
    }
    return 0;
}

