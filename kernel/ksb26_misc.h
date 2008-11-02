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

static char *ksb26_ntoa(unsigned long saddr)
{
    static char buff[18];
    char *p;

    p = (char *)&saddr;
    sprintf(buff, "%d.%d.%d.%d", (*p & 255), (*(p + 1) & 255), (*(p + 2) & 255), \
            (*(p + 3) & 255));
    return buff;
}                                                        

static int ksb26_atoi(char *str)
{
    int i, n = 0;

    if(!str) return -1;
    for(i = 0; str[i] < '0' || str[i] > '9'; ++i);
    for(n = 0; str[i] != '\0' && str[i] >= '0' && str[i] <= '9'; ++i) n = 10 * n + (str[i] - '0');
    return n;
}

static int ksb26_isip(char *ip)
{
	int pcnt = 0;
	char *ptr;

	if(!ip) return 0;
	for(ptr = ip; *ptr != '\0'; ptr++) if(*ptr == '.') pcnt++;
	if(pcnt != 3) return 0;
	for(pcnt = 0; pcnt < 3; pcnt++) {
		if(ksb26_atoi(ptr) < 0 || ksb26_atoi(ptr) > 255) return 0;
		if(!(ptr = strchr(ip, '.'))) return 0;
		ptr++;
		ip = ptr;
	}
	return 1;
}

static int ksb26_istcpport(int port) {
	if(port < 1 || port > 65535) return 0;
	return 1;
}

static int ksb26_getline(char *string, int init_ch, int end_ch, char **line)
{
	char *aux = NULL;
  
	*line = NULL;
	if (!string) return 0;
        if(init_ch != -1) {
            if(!(aux = strchr(string, init_ch))) return 0;
            aux++;
        } else aux = string;
        string = aux;
        if(end_ch != -1) {
            if(!(aux = strchr(string, end_ch))) { aux = string; while(*(aux + 1)) aux++; }
        } else { aux = string; while(*(aux + 1)) aux++; }
        *line = kmalloc((int)(aux - string + 1) * sizeof(char), GFP_KERNEL);
        snprintf(*line,(int)(aux - string + 1), "%s", string);
	return aux - string;
}

