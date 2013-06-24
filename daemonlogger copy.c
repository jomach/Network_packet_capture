/* $Id: daemonlogger.c,v 1.21 2008/11/24 19:56:48 roesch Exp $ */

/*************** IMPORTANT DAEMONLOGGER LICENSE TERMS **************** 
* 
* This Daemonlogger software is the copyrighted work of Sourcefire, Inc.
* (C) 2007 Sourcefire, Inc.  All Rights Reserved.  This program is free
* software; you may use, redistribute and/or modify this software only under
* the terms and conditions of the GNU General Public License as published by
* the Free Software Foundation; Version 2 with the clarifications and
* exceptions described below.  If you wish to embed this Daemonlogger
* technology into proprietary software, we sell alternative licenses (contact
* snort-license@sourcefire.com). 
* 
* Note that the GPL requires that any work that contains or is derived from
* any GPL licensed work also must be distributed under the GPL.  However,
* there exists no definition of what is a "derived work."  To avoid
* misunderstandings, we consider an application to constitute a "derivative
* work" for the purpose of this license if it does any of the following: 
* - Integrates source code from Daemonlogger.
* - Includes Daemonlogger copyrighted data files.
* - Integrates/includes/aggregates Daemonlogger into a proprietary executable
*   installer, such as those produced by InstallShield.
* - Links to a library or executes a program that does any of the above where
*   the linked output is not available under the GPL.
* 
* The term "Daemonlogger" should be taken to also include any portions or
* derived works of Daemonlogger.  This list is not exclusive, but is just
* meant to clarify our interpretation of derived works  with some common
* examples.  These restrictions only apply when you actually redistribute
* Daemonlogger.  For example, nothing stops you from writing and selling a
* proprietary front-end to Daemonlogger.  Just distribute it by itself, and
* point people to http://www.snort.org/dl to download Daemonlogger.
* 
* We don't consider these to be added restrictions on top of the GPL, but just
* a clarification of how we interpret "derived works" as it applies to our
* GPL-licensed Snort product.  This is similar to the way Linus Torvalds has
* announced his interpretation of how "derived works" applies to Linux kernel
* modules.  Our interpretation refers only to Daemonlogger - we don't speak
* for any other GPL products.
* 
* If you have any questions about the GPL licensing restrictions on using
* Daemonlogger in non-GPL works, we would be happy to help.  As mentioned
* above, we also offer alternative license to integrate Daemonlogger into
* proprietary applications and appliances.  These contracts can generally
* include a perpetual license as well as providing for priority support and
* updates as well as helping to fund the continued development of Daemonlogger
* technology.  Please email snort-license@sourcefire.com for further
* information.
* 
* If you received these files with a written license agreement or contract
* stating terms other than the terms above, then that alternative license
* agreement takes precedence over these comments.
* 
* Source is provided to this software because we believe users have a right to
* know exactly what a program is going to do before they run it. This also
* allows you to audit the software for security holes.
* 
* Source code also allows you to port Daemonlogger to new platforms, fix bugs,
* and add new features.  You are highly encouraged to send your changes to
* roesch@sourcefire.com for possible incorporation into the main distribution.
* By sending these changes to Sourcefire or one of the Sourcefire-moderated
* mailing lists or forums, you are granting to Sourcefire, Inc. the unlimited,
* perpetual, non-exclusive right to reuse, modify, and/or relicense the code.
* Daemonlogger will always be available Open Source, but this is important 
* because the inability to relicense code has caused devastating problems for
* other Free Software projects (such as KDE and NASM).  We also occasionally
* relicense the code to third parties as discussed above.  If you wish to
* specify special license conditions of your contributions, just say so when
* you send them. 
* 
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; including without limitation any implied warranty of 
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
* Public License for more details at http://www.gnu.org/copyleft/gpl.html, 
* or in the COPYING file included with Daemonlogger. 
* 
*/ 

/*
** Copyright (C) 2006 Sourcefire Inc. All Rights Reserved.
** Author: Martin Roesch <roesch@sourcefire.com>
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <dirent.h>
#include <syslog.h>
#include <pcap.h>
#include <dnet.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/mount.h>

#ifdef LINUX
#include <sys/statvfs.h>
#include <sys/vfs.h>
#endif

#define SUCCESS     0
#define ERROR       1
#define STDBUF      1024
#define KILOBYTE    1 << 10
#define MEGABYTE    1 << 20
#define GIGABYTE    1 << 30
#define TERABYTE    1 << 40

#ifndef VERSION
#define VERSION     "1.2.0"
#endif

#define _FILE_OFFSET_BITS   64

#define PRUNE_OLDEST_ABSOLUTE   0
#define PRUNE_OLDEST_IN_RUN     1

/* Fix for broken linux <sys/queue.h> */
#ifndef HAVE_TAILQFOREACH
#define _EVENT_DEFINED_TQENTRY
#define TAILQ_ENTRY(type)                       \
struct {                                \
        struct type *tqe_next;  /* next element */          \
        struct type **tqe_prev; /* address of previous next element */  \
}
#define TAILQ_FIRST(head)       ((head)->tqh_first)
#define TAILQ_END(head)         NULL
#define TAILQ_NEXT(elm, field)      ((elm)->field.tqe_next)
#define TAILQ_FOREACH(var, head, field)                 \
    for((var) = TAILQ_FIRST(head);                  \
        (var) != TAILQ_END(head);                   \
        (var) = TAILQ_NEXT(var, field))
#define TAILQ_INSERT_BEFORE(listelm, elm, field) do {           \
    (elm)->field.tqe_prev = (listelm)->field.tqe_prev;      \
    (elm)->field.tqe_next = (listelm);              \
    *(listelm)->field.tqe_prev = (elm);             \
    (listelm)->field.tqe_prev = &(elm)->field.tqe_next;     \
} while (0)
#endif /* TAILQ_FOREACH */

typedef enum {
    MINUTES=1,
    HOURS,
    DAYS
    } interval;

static char *interval_names[] = {
    "none",
    "minutes",
    "hours",
    "days"
};

typedef enum {
    KILOBYTES = 1,
    MEGABYTES,
    GIGABYTES,
    TERABYTES
    } size;
    
static char *size_names[] = {
    "none",
    "kilobytes",
    "megabytes",
    "gigabytes",
    "terabytes"
};

typedef struct filelist Filelist;

struct file_entry
{
    TAILQ_ENTRY(file_entry) next;
    char *filename;
};

TAILQ_HEAD(filelist, file_entry);

static Filelist file_list;

static int count;
static int daemon_mode;
static int rollover;
static int maxfiles;
static int filecount;
static int showver;
static int datalink;
static int shutdown_requested;
static int restart_requested;
static int ringbuffer;
static int use_syslog;
static int readback_mode;
static int snaplen;
static int drop_privs_flag;
static int chroot_flag;
static int rollover_interval;
static int flush_flag;
static int maxpct;
static int prune_flag;

static char *interface;
static char *retrans_interface;
static char *logpath;
static char *logfilename;
static char *pcap_cmd;
static char *readfile;
static char *pidfile = "daemonlogger.pid";
static char *pidpath = "/var/run";
static char *true_pid_name;
static char *group_name;
static char *user_name;
static char *chroot_dir;
static char logdir[STDBUF];
static char testpath[STDBUF];

static size_t rollsize;
static time_t lastroll;
static time_t nextroll;
static u_int64_t rollsize_in_blocks;

static pcap_t *pd;
static pcap_dumper_t *pdp;

static eth_t *eth_retrans;

static u_int64_t part_total_blocks;
static u_int64_t part_min_free_blocks;

void (*packet_handler)(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt);
static int sniff_loop();
static int set_rollover_time();

#ifdef LINUX
#define d_statfs(p, s) statvfs(p, s)
typedef struct statvfs d_statfs_t; 
#elif MACOSX
#define d_statfs(p, s) statfs64(p, s)
typedef struct statfs64 d_statfs_t;
#else
#define d_statfs(p, s) statfs(p, s)
typedef struct statfs d_statfs_t;
#endif

static void fatal(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);

    if(use_syslog)
    {
        syslog(LOG_CONS | LOG_DAEMON | LOG_ERR, "FATAL ERROR: %s", buf);
    }
    else
    {
        fprintf(stderr, "ERROR: %s\n", buf);
        fprintf(stderr,"Fatal Error, Quitting..\n");        
    }

    va_end(ap);

    exit(1);
}

static void msg(const char *format, ...)
{
    char buf[STDBUF+1];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, STDBUF, format, ap);

    if(use_syslog)
    {
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", buf);
    }
    else
    {
        fprintf(stderr, "%s\n", buf);
    }
    va_end(ap);
}

static int is_valid_path(char *path)
{
    struct stat st;

    if(path == NULL)
        return 0;
        
    if(stat(path, &st) != 0)
        return 0;

    if(!S_ISDIR(st.st_mode) || access(path, W_OK) == -1)
    {
        return 0;
    }
    return 1;
}

static int create_pid_file(char *path, char *filename)
{
    char filepath[STDBUF];
    char *fp = NULL;
    char *fn = NULL;
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    memset(filepath, 0, STDBUF);
    
    if(!filename)
        fn = pidfile;
    else
        fn = filename;
        
    if(!path)
        fp = pidpath;
    else
        fp = path;
    
    if(is_valid_path(fp))
        snprintf(filepath, STDBUF-1, "%s/%s", fp, fn);
    else
        fatal("PID path \"%s\" isn't a writeable directory!", fp);
    
    true_pid_name = strdup(filename);
    
    if((fd = open(filepath, O_CREAT | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
    {
        return ERROR;
    }

    /* pid file locking */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1)
    {
        if (errno == EACCES || errno == EAGAIN)
        {
            rval = ERROR;
        }
        else
        {
            rval = ERROR;
        }
        close(fd);
        return rval;
    }

    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int) getpid());
    ftruncate(fd, 0);
    write(fd, pid_buffer, strlen(pid_buffer));
    return SUCCESS;
}


//changes by Jorge

char current_file[200]; 

int daemonize()
{
    pid_t pid;
    int fd;

    pid = fork();

    if (pid > 0)
        exit(0); /* parent */

    use_syslog = 1;
    if (pid < 0)
        return ERROR;

    /* new process group */
    setsid();

    /* close file handles */
    if ((fd = open("/dev/null", O_RDWR)) >= 0)
    {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }

   if (pidfile) return create_pid_file(pidpath, pidfile);
    
    return SUCCESS;
}

char *get_filename()
{
    time_t currtime;

    memset(logdir, 0, STDBUF);
    currtime = time(NULL);
    if(logpath != NULL)
    {
        if(snprintf(logdir, 
                    STDBUF, 
                    "%s/%s.%lu", 
                    logpath, 
                    logfilename, 
                    (long unsigned int) currtime) < 0)
            return NULL;        
    }
    else
    {
        if(snprintf(logdir, 
                    STDBUF, 
                    "%s.%lu",
                    logfilename,
                    (long unsigned int) currtime) < 0)
            return NULL;        
    }

    return logdir;
}

static int go_daemon()
{
    return daemonize(NULL);
}

static void dl_shutdown(int signal)
{
    msg("Quitting!");
    if(retrans_interface != NULL) 
    {
        eth_close(eth_retrans);
    }
    else
    {
        if(pdp != NULL)
        {
            pcap_dump_flush(pdp);
            pcap_dump_close(pdp);
        }
    }
    
    if(pd != NULL)
        pcap_close(pd);

    if(true_pid_name != NULL)
        unlink(true_pid_name);
    
    exit(0);
}

static void quitter(int signal)
{
    shutdown_requested = 1;
    alarm(1);
}

static int prune_oldest_file_this_run()
{
    struct stat sb;
    struct file_entry *fe;
    
    while((fe = TAILQ_FIRST(&file_list)) != NULL)
    {
        if(fe->filename != NULL)
        {
            if(stat(fe->filename, &sb) != 0)
            {
                msg("[ERR] stat failed for \"%s\": %s\n", fe->filename, 
                    strerror(errno));
                TAILQ_REMOVE(&file_list, fe, next);
                free(fe->filename);
                free(fe);                    
            }
            else
            {
                if((sb.st_mode & S_IFMT) == S_IFREG)
                {
                    msg("[!] Ringbuffer: deleting %s", fe->filename);
                    unlink(fe->filename);
                    TAILQ_REMOVE(&file_list, fe, next);
                    free(fe->filename);
                    free(fe);
                    break;
                }                        
            }
        }
        else
        {
            TAILQ_REMOVE(&file_list, fe, next);
            free(fe);
        }
    }
    
    return 0;
}

static int prune_oldest_file_in_dir()
{
    DIR *dirp;
    struct dirent *dp;
    struct stat sb;
    time_t oldtime = 0;
    char *oldname = NULL;
    char fpath[STDBUF+1];
    
    memset(fpath, 0, STDBUF+1);
    if(logpath != NULL)
    {
        dirp = opendir(logpath);        
    }
    else
        dirp = opendir(".");
    
    if(dirp == NULL)
    {
        msg("opendir failed\n");
        return 0;
    }
    
    while((dp = readdir(dirp)) != NULL)
    {
        snprintf(fpath, STDBUF, "%s/%s", logpath?logpath:".", dp->d_name);
        if(stat(fpath, &sb) != 0)
            msg("stat failed for \"%s\": %s\n", fpath, strerror(errno));

        if((sb.st_mode & S_IFMT) == S_IFREG)
        {
            if(strstr(dp->d_name, logfilename))
            {
                if(oldtime == 0 || sb.st_mtime < oldtime)
                {
                    oldtime = sb.st_mtime;
                    if(oldname != NULL)
                    {
                        free(oldname);
                    }
                    oldname = strdup(fpath);
                }                                            
            }
        }
    }

    closedir(dirp);
    msg("[!] Ringbuffer: deleting %s", oldname);
    if(*oldname != 0)
        unlink(oldname);
    return 0;
}

static int open_log_file()
{
    struct file_entry *fe;
    char *filepath = get_filename();
    
    if(maxfiles == 0 || (maxfiles > 0 && filecount > 0))
    {
        if(maxfiles > 0)
        {
            filecount--;
            if(ringbuffer == 0)
                msg("%d files to go before quitting", filecount+1);
        }
    }
    else
    {
        if(ringbuffer == 0)
        {
            msg("Max file count reached, exiting");
            quitter(1);
            return ERROR;            
        }
        else
        {
            if(prune_flag == PRUNE_OLDEST_IN_RUN)
                prune_oldest_file_this_run();
            else
                prune_oldest_file_in_dir();
        }
    }
    
    if(maxpct != 0)
    {
        d_statfs_t s;
        if(d_statfs(testpath, &s) != 0)
        {
            perror("Unable to stat partition!\n");
            fatal("EPIC FAIL!");
        }
        
        if((s.f_bavail - rollsize_in_blocks) < part_min_free_blocks)
        {
            msg("Disk max utilization reached, rolling over and pruning");
            if(prune_flag == PRUNE_OLDEST_IN_RUN)
                prune_oldest_file_this_run();
            else
                prune_oldest_file_in_dir();
        }
    }
    
    if(filepath != NULL)
    {
        if(ringbuffer == 1)
        {
            fe = calloc(sizeof(struct file_entry), sizeof(char));
            if((fe->filename = strdup(filepath)) != NULL)
            {
                if(prune_flag == PRUNE_OLDEST_IN_RUN)
                    TAILQ_INSERT_TAIL(&file_list, fe, next);
#ifdef DEBUG
                msg("File_list contents:\n");
                TAILQ_FOREACH(fe, &file_list, next)
                {
                    msg("   %s\n", fe->filename);             
                }
#endif
            }
            else
            {
                fatal("Lurene sez ur fucked\n");
            }
        }

        msg("Logging packets to %s", filepath);
        if((pdp = pcap_dump_open(pd, filepath)) == NULL)
        {
            fatal("Unable to open log file %s\n", pcap_geterr(pd));
        }
      strcpy(current_file,filepath);
    }
    else
        return ERROR;

    return SUCCESS;
}

static int drop_privs(void)
{
    struct group *gr;
    struct passwd *pw;
    char *endptr;
    int i;
    int do_setuid = 0;
    int do_setgid = 0;
    unsigned long groupid = 0;
    unsigned long userid = 0;

    if(group_name != NULL)
    {
        do_setgid = 1;
        if(isdigit(group_name[0]) == 0)
        {
            gr = getgrnam(group_name);
            groupid = gr->gr_gid;
        }
        else
        {
            groupid = strtoul(group_name, &endptr, 10);
        }        
    }
    
    if(user_name != NULL)
    {
        do_setuid = 1;
        do_setgid = 1;
        if(isdigit(user_name[0]) == 0)
        {
            pw = getpwnam(user_name);
            userid = pw->pw_uid;
        }
        else
        {
            userid = strtoul(user_name, &endptr, 10);
            pw = getpwuid(userid);
        }
        
        if(group_name == NULL)
            groupid = pw->pw_gid;
    }

    if(do_setgid)
    {
        if((i = setgid(groupid)) < 0)
            fatal("Unable to set group ID: %s", strerror(i));
    }
    
    endgrent();
    endpwent();
    
    if(do_setuid)
    {
        if(getuid() == 0 && initgroups(user_name, groupid) < 0)
            fatal("Unable to init group names (%s/%lu)", user_name, groupid);
        if((i = setuid(userid)) < 0)
            fatal("Unable to set user ID: %s\n", strerror(i));
    }
    
    return 0;
}

char *get_abs_path(char *dir)
{
    char *savedir, *dirp;

    if(dir == NULL)
    {
        return NULL;
    }

    if((savedir = getcwd(NULL, 0)) == NULL)
    {
        msg("ERROR: getcwd() failed: %s", strerror(errno));
        return NULL;
    }

    if(chdir(dir) < 0)
    {
        msg("ERROR: Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = getcwd(NULL, 0);
    
    if(chdir(savedir) < 0)
    {
        msg("Can't change back to directory: %s\n", dir);
        free(savedir);                
        return NULL;
    }

    free(savedir);
    return (char *) dirp;
}

static int set_chroot(void)
{
    char *absdir;
    int abslen;
    char *logdir;
    
    logdir = get_abs_path(logpath);

    /* change to the directory */
    if(chdir(chroot_dir) != 0)
    {
        fatal("set_chroot: Can not chdir to \"%s\": %s\n", chroot_dir, 
              strerror(errno));
    }

    /* always returns an absolute pathname */
    absdir = getcwd(NULL, 0);
    abslen = strlen(absdir);
    
    /* make the chroot call */
    if(chroot(absdir) < 0)
    {
        fatal("Can not chroot to \"%s\": absolute: %s: %s\n",
               chroot_dir, absdir, strerror(errno));
    }

    if(chdir("/") < 0)
    {
        fatal("Can not chdir to \"/\" after chroot: %s\n", 
               strerror(errno));
    }    

    return 0;
}

static int init_retrans()
{
    if((eth_retrans = eth_open(retrans_interface)) == NULL)
        fatal("init_retrans() eth_open failed\n");
        
    return 0;
}

static int start_sniffing()
{
    bpf_u_int32 localnet, netmask;         /* net addr holders */
    struct bpf_program fcode;              /* Finite state machine holder */
    char errorbuf[PCAP_ERRBUF_SIZE];       /* buffer to put error strings in */
    bpf_u_int32 defaultnet = 0xFFFFFF00;    

    if(readback_mode == 0)
    {
        if(interface == NULL)
        {
            interface = pcap_lookupdev(errorbuf);
            if(interface == NULL)
            {
                fatal("start_sniffing() interface lookup: \n\t%s\n", errorbuf);
            }
        }

        msg("sniffing on interface %s", interface);
        pd = pcap_open_live(interface, 
                            snaplen?snaplen:65535, 
                            1, 
                            500, 
                            errorbuf);

        if(pd == NULL)
        {
            fatal("start_sniffing(): interface %s open: %s\n", 
                    interface, 
                    errorbuf);
        }        
    }
    else
    {
        msg("Reading network traffic from \"%s\" file.\n", readfile);
        pd = pcap_open_offline(readfile, errorbuf);
        if(pd == NULL)
        {
            fatal("unable to open file \"%s\" for readback: %s\n",
                  readfile, errorbuf);
        }

        snaplen = pcap_snapshot(pd);
        msg("snaplen = %d\n", snaplen);
    }

    if(pcap_lookupnet(interface, &localnet, &netmask, errorbuf) < 0)
    {
        msg("start_sniffing() device %s network lookup: "
             "\t%s",
             interface,
             errorbuf);

        netmask = htonl(defaultnet);
    }

    if(pcap_compile(pd, &fcode, pcap_cmd, 1, netmask) < 0)
    {
        fatal("start_sniffing() FSM compilation failed: \n\t%s\n"
                "PCAP command: %s\n", pcap_geterr(pd), pcap_cmd);
    }

    /* set the pcap filter */
    if(pcap_setfilter(pd, &fcode) < 0)
    {
        fatal("start_sniffing() setfilter: \n\t%s\n",
                pcap_geterr(pd));
    }

    /* get data link type */
    datalink = pcap_datalink(pd);

    if(datalink < 0)
    {
        fatal("OpenPcap() datalink grab: \n\t%s\n",
                pcap_geterr(pd));
    }
    return 0;
}

static int log_rollover()
{
    msg("Rolling over logfile...");
    if(pdp != NULL)
    {
	
	pcap_dump_flush(pdp);
    pcap_dump_close(pdp);
    pdp = NULL;
	 
	}
	signal(SIGCHLD, SIG_IGN);
	if(!fork()){
		//execute the python script here
		char str1[] ="./encrypt.py ";
		strcat(str1,current_file);
		system(str1);
		exit(0);
	}
    open_log_file();
    return SUCCESS;
}

static void dl_restart()
{
    restart_requested = 0;

    if(retrans_interface == NULL)
    {
        pcap_dump_flush(pdp);
        pcap_dump_close(pdp);
    }
    else
    {
        eth_close(eth_retrans);
    }
    
    pcap_close(pd);     
    start_sniffing();
    sniff_loop();   
}

static void restarter(int signal)
{
    msg("Caught SIGHUP, restarting...");
    restart_requested = 1;
}

static char *load_bpf_file(char *filename)
{
    int fd;
    int readbytes;
    char *filebuf;
    char *comment;
    struct stat buf;
    
    if((fd = open(filename, O_RDONLY)) < 0)
        fatal("Unable to open BPF filter file %s: %s\n", 
              filename, 
              pcap_strerror(errno));
              
    if(fstat(fd, &buf) < 0)
        fatal("Stat failed on %s: %s\n", filename, pcap_strerror(errno));
        
    filebuf = calloc((unsigned int)buf.st_size + 1, sizeof(unsigned char));

    if((readbytes = read(fd, filebuf, (int) buf.st_size)) < 0)
        fatal("Read failed on %s: %s\n", filename, pcap_strerror(errno));
    
    if(readbytes != buf.st_size)
        fatal("Read bytes != file bytes on %s (%d != %d)\n",
              filename, readbytes, (int) buf.st_size);
              
    filebuf[(int)buf.st_size] = '\0';
    close(fd);
    
    /* strip comments and <CR>'s */
    while((comment = strchr(filebuf, '#')) != NULL)
    {
        while(*comment != '\r' && *comment != '\n' && comment != '\0')
        {
            *comment++ = ' ';
        }
    }
    
    return (filebuf);
}

void packet_dump(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    time_t now;
    
    if(rollover)
    {
        now = time(NULL);
        if(rollover_interval == 0)
        {
            if(lastroll + rollover < now)
            {
                msg("Rollover timer has expired!");
                log_rollover();
                lastroll = now;    
            }            
        }
        else
        {
            if(now > nextroll)
            {
                msg("Rollover timer has expired!");
                log_rollover();
                set_rollover_time();
            }
        }
    }
    
    if(shutdown_requested == 1)
        dl_shutdown(0);
    
    if(restart_requested == 1)
        dl_restart();

    pcap_dump((u_char *) pdp, pkthdr, pkt);
    if(flush_flag)
        pcap_dump_flush(pdp);
        
    if(((size_t)ftello((FILE *) pdp)) > rollsize)
    {
        msg("Size limit reached (%zd - %zd = %zd), rolling over!", 
            (size_t)ftell((FILE *) pdp), rollsize,
            (size_t) ftell((FILE *) pdp) - rollsize);
        log_rollover();
    }
    
    return;
}

void packet_retrans(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
    eth_send(eth_retrans, pkt, pkthdr->caplen);
    
    if(shutdown_requested)
        dl_shutdown(0);
    if(restart_requested)
        dl_restart();
        
    return;
}

static int sniff_loop()
{
    if(chroot_flag)
        set_chroot();

    if(retrans_interface != NULL) 
    {
        init_retrans();        
        if(drop_privs_flag)
            drop_privs();
    }
    else
    {
        if(drop_privs_flag)
            drop_privs();
        open_log_file();        
    }

    lastroll = time(NULL);

    /* Read all packets on the device.  Continue until cnt packets read */
    if(pcap_loop(pd, count, (pcap_handler) packet_handler, NULL) < 0)
    {
        msg("pcap_loop: %s", pcap_geterr(pd));

        quitter(1);
    }

    return SUCCESS;
}


char *copy_argv(char **argv)
{
    char **p;
    u_int len = 0;
    char *buf;
    char *src, *dst;
    void ftlerr(char *,...);

    p = argv;
    if(*p == 0)
        return NULL;

    while(*p)
        len += strlen(*p++) + 1;

    buf = (char *) malloc(len);

    if(buf == NULL)
    {
        fatal("malloc() failed: %s\n", strerror(errno));
    }
    p = argv;
    dst = buf;

    while((src = *p++) != NULL)
    {
        while((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    return buf;
}

static int set_rollover_time()
{
    time_t now;
    struct tm *curtime;
    
    now = time(NULL);
    curtime = localtime(&now);
    
    switch(rollover_interval)
    {
        case MINUTES:
            curtime->tm_min += rollover;
            curtime->tm_sec = 0;
            break;
        case HOURS:
            curtime->tm_hour += rollover;
            curtime->tm_min = 0;
            curtime->tm_sec = 0;
            break;
        case DAYS:
            curtime->tm_mday += rollover;
            curtime->tm_hour = 0;
            curtime->tm_min = 0;
            curtime->tm_sec = 0;
            break;  
    }
    nextroll = mktime(curtime);
    return 0;
}
static void usage()
{
    printf("USAGE: daemonlogger [-options] <bpf filter>\n");
    printf("        -c <count>      Log <count> packets and exit\n");
    printf("        -d              Daemonize at startup\n");
    printf("        -f <bpf file>   Load BPF filter from <bpf file>\n");
    printf("        -F              Flush the pcap buffer for each packet\n");
    printf("        -g <group name> Set group ID to <group name>\n");
    printf("        -h              Show this usage statement\n");
    printf("        -i <intf>       Grab packets from interface <intf>\n");
    printf("        -l <path>       Log to directory <path>\n");
    printf("        -m <count>      Generate <count> log files and quit\n");
    printf("        -M <pct>        In ringbuffer mode log data to <pct> of\n"
           "                        volume capacity\n");
    printf("        -n <name>       Set output filename prefix to <name>\n");
    printf("        -o <outf>       Disable logging, retransmit data from\n"
           "                        <intf> to <outf>\n");
    printf("        -p <pidfile>    Use <pidfile> for PID filename\n");
    printf("        -P <pidpath>    Use <pidpath> for PID directory\n");
    printf("        -r              Activate ringbuffer mode\n");
    printf("        -R <pcap file>  Read packets from <pcap file>\n");
    printf("        -s <bytes>      Rollover the log file every <bytes>\n");
    printf("        -S <snaplen>    Capture <snaplen> bytes per packet\n");
    printf("        -t <time>       Rollover the log file on time intervals\n");
    printf("        -u <user name>  Set user ID to <user name>\n");
    printf("        -v              Show daemonlogger version\n");
}

extern char *optarg;
extern int  optind, opterr, optopt;

int parse_cmd_line(int argc, char *argv[])
{
    int ch = 0;
    char rollmetric = 0;
    char rollenum = 0;
    size_t  rollpoint = 0;
    char *endptr = NULL;
    char *bpf_filename = NULL;
    int bpf_file = 0;

    while((ch = getopt(argc, argv, 
            "c:df:Fg:hi:l:m:M:n:o:p:P:rR:s:S:t:T:u:vz"))!=-1)
    {
        switch(ch)
        {
            case 'c':
                count = atoi(optarg);
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'f':
                bpf_filename = strdup(optarg);
                bpf_file = 1;
                break;
            case 'F':
                flush_flag = 1;
                break;
            case 'g':
                group_name = strdup(optarg);
                drop_privs_flag = 1;
                break;
            case 'h':
                usage();
                exit(0);
                break;
            case 'i':
                interface = strdup(optarg);
                break;
            case 'l':
                logpath = strdup(optarg);
                break;
            case 'm':
                maxfiles = atoi(optarg);
                filecount = maxfiles;
                break;
            case 'M':
                maxpct = atoi(optarg);
                if(maxpct > 100 || maxpct < 0)
                    fatal("Bad max percent argument: %s\n", optarg);
                break;
            case 'n':
                free(logfilename);
                logfilename = strdup(optarg);
                break;
            case 'o':
                retrans_interface = strdup(optarg);
                packet_handler = packet_retrans;

                break;
            case 'p':
                pidfile = strdup(optarg);
                break;
            case 'P':
                pidpath = strdup(optarg);
                break;
            case 'r':
                ringbuffer = 1;
                break;
            case 'R':
                readback_mode = 1;
                readfile = strdup(optarg);
                break;
            case 's':
                if(isdigit((int)optarg[strlen(optarg)-1]))
                {
                    rollsize = strtoul(optarg, &endptr, 10);    
                    if(endptr == optarg)
                    {
                        fprintf(stderr, "Bad rollover size, defaulting to 2GB\n");
                        rollsize = GIGABYTE;
                    }
                }
                else
                {
                    sscanf(optarg, "%zu%c", &rollpoint, &rollmetric);
                    
                    switch(tolower(rollmetric))
                    {
                        case 'k':
                            rollenum = KILOBYTES;
                            rollsize = rollpoint * KILOBYTE;
                            break;
                        case 'm':
                            rollsize = rollpoint * MEGABYTE;
                            rollenum = MEGABYTES;
                            break;
                        case 'g':
                            rollsize = rollpoint * GIGABYTE;
                            rollenum = GIGABYTES;
                            break;
                        case 't':
                            rollsize = (u_int64_t) rollpoint * TERABYTE;
                            rollenum = TERABYTES;                            
                            break;
                        default:
                            fatal("Bad size argument \"%c\"\n", 
                                  rollmetric);
                            break;
                    }
                }
                break;
            case 'S':
                if(!isdigit(optarg[0]))
                    fatal("Bad snaplen argument \"%s\"\n", optarg);
                snaplen = atoi(optarg);
                break;
            case 't':
                if(isdigit((int)optarg[strlen(optarg)-1]))
                {
                     rollover = atoi(optarg); 
                }
                else
                {
                    sscanf(optarg, "%d%c", &rollover, &rollmetric);
                    
                    switch(tolower(rollmetric))
                    {
                        case 'm':
                            rollover_interval = MINUTES;
                            break;
                        case 'h':
                            rollover_interval = HOURS;
                            break;
                        case 'd':
                            rollover_interval = DAYS;
                            break;
                        default:
                            fatal("Bad time interval argument \"%c\"\n", 
                                  rollmetric);
                            break;
                    }
                }
                break;
            case 'T':
                chroot_dir = strdup(optarg);
                chroot_flag = 1;
                break;
            case 'u':
                user_name = strdup(optarg);
                drop_privs_flag = 1;
                break;
            case 'v':
                showver = 1;
                break;
            case 'z':
                prune_flag = PRUNE_OLDEST_IN_RUN;
                break;
            default:
                break;          
        }
    }

    if(bpf_file == 0)
        pcap_cmd = copy_argv(&argv[optind]);
    else
        pcap_cmd = load_bpf_file(bpf_filename);
    
    if(ringbuffer == 1 && prune_flag == PRUNE_OLDEST_IN_RUN)
        TAILQ_INIT(&file_list);
    
    if(count)
        printf("[-] Configured to log %d packets\n", count);
    if(daemon_mode)
        printf("[-] Daemon mode set\n");
    if(bpf_file)
        printf("[-] Reading BPF filter in from file %s\n", bpf_filename);
    if(flush_flag)
        printf("[-] Packet-buffered output activated\n");
    if(drop_privs_flag)
        printf("[-] Setting group ID to %s\n", group_name);
    if(interface != NULL)
        printf("[-] Interface set to %s\n", interface);
    if(logpath != NULL)
        printf("[-] Logpath set to %s\n", logpath);
    if(filecount)
        printf("[-] Max files to write set to %d\n", maxfiles);
    if(logfilename != NULL)
        printf("[-] Log filename set to \"%s\"\n", logfilename);
    if(retrans_interface != NULL)
        printf("[-] Tap output interface set to %s", retrans_interface);
    if(pidfile)
        printf("[-] Pidfile configured to \"%s\"\n", pidfile);
    if(pidpath)
        printf("[-] Pidpath configured to \"%s\"\n", pidpath);
    if(ringbuffer)
        printf("[-] Ringbuffer active\n");
    if(readback_mode)
        printf("[-] In readback mode\n");
    if(rollpoint != 0)
        printf("[-] Rollover configured for %zu %s\n", 
                rollpoint, size_names[(int)rollenum]);
    else
        printf("[-] Rollover size set to %lu bytes\n", 
                (unsigned long) rollsize);
    if(snaplen)
        printf("[-] Snaplen set to %d\n", snaplen);
    if(rollmetric != 0)
        printf("[-] Rollover configured for %d %s\n", 
                rollover, interval_names[rollover_interval]);
    else
        printf("[-] Rollover time configured for %d seconds\n", 
                rollover);
    if(chroot_flag)
        printf("[-] Setting chroot directory to %s", chroot_dir);
    if(drop_privs_flag)
        printf("[-] Setting user ID to %s\n", user_name);
    if(prune_flag == PRUNE_OLDEST_IN_RUN)
        printf("[-] Pruning behavior set to oldest THIS RUN\n");
    else
        printf("[-] Pruning behavior set to oldest IN DIRECTORY\n");

    return SUCCESS;
}

int main(int argc, char *argv[])
{   
    sigset_t set;
    packet_handler = packet_dump;
    int statret;
    d_statfs_t s;
    
    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);

    /* Make this prog behave nicely when signals come along.
     * Windows doesn't like all of these signals, and will
     * set errno for some.  Ignore/reset this error so it
     * doesn't interfere with later checks of errno value.
     */
    signal(SIGTERM, quitter);    if(errno!=0) errno=0;
    signal(SIGINT, quitter);     if(errno!=0) errno=0;
    signal(SIGQUIT, quitter);    if(errno!=0) errno=0;
    signal(SIGHUP, restarter);   if(errno!=0) errno=0;
    signal(SIGALRM, dl_shutdown);  if(errno!=0) errno=0;
    
    rollsize = 2*GIGABYTE;

    logfilename = strdup("daemonlogger.pcap");

    parse_cmd_line(argc, argv);

    printf("\n-*> DaemonLogger <*-\n"
           "Version %s\n"
           "By Martin Roesch\n"
           "(C) Copyright 2006-2007 Sourcefire Inc., All rights reserved\n\n"
           , VERSION);    

    if(showver) exit(0);

    if(logpath != NULL && !is_valid_path(logpath))
        fatal("Log path \"%s\" is bad", logpath);
        
    if(logpath != NULL)
    {
        snprintf(testpath, STDBUF-1, "%s/.", logpath);
        msg("Checking partition stats for log directory \"%s\"", testpath);
        if((statret = d_statfs(testpath, &s)) != 0)
        {
            fatal("Unable to stat partition!\n\"%s\"\n", strerror(statret));
        }
        else
        {
            if(maxpct)
            {
                double pct;
                double value;
                
                part_total_blocks = s.f_blocks;
                pct = ((double) maxpct)/100.0;
                value = ((double)part_total_blocks) * pct;
                part_min_free_blocks = part_total_blocks - ((u_int64_t) value);
                msg("%d%% max disk utilization = %llu blocks free (out of %llu)", 
                    maxpct, part_min_free_blocks, part_total_blocks);
                rollsize_in_blocks = (u_int64_t) (rollsize/(size_t)s.f_bsize);
                msg("Blocksize = %lu", s.f_bsize);
                msg("Rollsize = %llu blocks\n", rollsize_in_blocks);
            }
        }
    }
    
    if(daemon_mode) 
    {
        if(!is_valid_path(pidpath))
            fatal("PID path \"%s\" is bad, privilege problem usually",pidpath);
        
        openlog("daemonlogger", LOG_PID | LOG_CONS, LOG_DAEMON);
        go_daemon();
    }
    
    start_sniffing();
    if (rollover_interval != 0) 
    {
        set_rollover_time();
    }

    sniff_loop();
    return 0;
}
