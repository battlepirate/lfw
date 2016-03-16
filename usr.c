    #include <stdio.h>  
    #include <getopt.h>   
    #include <sys/ioctl.h>   
    #include <fcntl.h>  
    #include <string.h>
    #include <time.h>
    #include <ctype.h>

    #include "lwfw.h"  
    #define MAX 10

      
    char* const short_options = "adgctuiprwlx:y:";   
   char *wday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    
    struct option long_options[] = {  
        { "active"  , 0, NULL, 'a' },  
        { "deactive"    , 0, NULL, 'd' },  
        { "getstatus"   , 0, NULL, 'g' },  
        { "cleanlog" , 0, NULL, 'c' },
        { "tcp" , 0,NULL,'t'},
        { "udp" , 0,NULL,'u'},
        { "icmp" , 0,NULL,'i'},
        { "permit", 0, NULL,'p'},
        { "remove", 0, NULL,'r'},
        {"watch",0,NULL,'w'},
        {"load ", 0,NULL,'l'},
        {"start time",1,NULL,'x'},
        {"end time",1,NULL,'y'},    
        { 0     , 0, NULL,  0  },  
    };   
      
    int main(int argc, char *argv[])  
    {  
        int c;   
        char str[5];
        int num=0;
        int fd;  
        int type = 0;
        int permit=0;
        int delete=0;
        struct lwfw_stats status;  
        FILE *fp,*fphis;
        time_t timep;
        struct tm *p;
        struct rules infile[10];
        char deny_ip_src[17];
        char deny_ip_dest[17];
        char deny_if[10];
        unsigned char deny_port_src[9] = "\x00\x16"; //22
        unsigned int dps=0;
        unsigned char deny_port_dest[9] = "\x00\x16";
        unsigned int dpd = 0;
        int flag[4]={0,0,0,0};
        unsigned int i;
        int sig;

        struct rules buff;
        buff.src.deny_ip=0;
        buff.dest.deny_ip=0;
        buff.src.deny_port=0;
        buff.dest.deny_port=0;
        buff.permit=0;
        buff.type=0;
        buff.dropped=0;
        buff.start.hour = 0;
        buff.end.hour = 0;

        fd = open("/dev/lwfw",O_RDWR);  
        if(fd == -1 ){  
            perror("open");  
            return 0;  
        }

  for (i = 1; i < argc; i++){
                if(!flag[0] && !strncmp(argv[i],"ipsrc=",6)){
                        strcpy(deny_ip_src,argv[i]+6);
                        flag[0]=1;
                }
                else if(!flag[1] && !strncmp(argv[i],"ipdst=",6)){
                        strcpy(deny_ip_dest,argv[i]+6);
                        flag[1]=1;
                }
                else if(!flag[2] && !strncmp(argv[i],"ptsrc=",6)){
                        strcpy(deny_port_src,argv[i]+6);
                        dps=atoi(deny_port_src);
                        if(type == 0)    type = 1;
                        flag[2]=1;
                }
                else if(!flag[3] && !strncmp(argv[i],"ptdst=",6)){
                        strcpy(deny_port_dest,argv[i]+6);
                        dpd=atoi(deny_port_dest);
                        if(type == 0)       type=1;
                        flag[3]=1;
                }
        } 

    if((flag[0]||flag[1]||flag[2]||flag[3]||type)&&!delete){
             if(ioctl(fd,LWFW_SET) == -1)
             {
                      perror("ioctl LWFW_SET fail!\n");
                      return -1;
            }
            printf("set rules!\n");
        }

        while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1)  {  
            switch(c){  
                case 'a':  
                    ioctl(fd,LWFW_ACTIVATE);  
                    return 0;  
                case 'd':  
                    ioctl(fd,LWFW_DEACTIVATE);  
                    return 0;  
                case 'g':  
                    ioctl(fd,LWFW_GET_STATS,status);  
                    printf("total_dropped is %x\n",status.total_dropped);  
                    printf("total_seen is %x\n",status.total_seen);  
                    break;  
                case 'w':
                     if((fp=fopen("log","w+"))==NULL){
                             printf("Cannot open file log!\n");
                                return -1;
                        }
                        fclose(fp);
                        fp=fopen("log","a+");
                    if((fphis=fopen("history.txt","a+"))==NULL){
                             printf("Cannot open file !");
                                return -1;
                        }
                    do{
                        sig = ioctl(fd,LWFW_W,&buff.src.deny_ip) ;
                     if(sig == 1){
                        printf("no rules!\n");
                        return 0;
                    }
                     printf("source ip: %d.%d.%d.%d\n",
                            buff.src.deny_ip   & 0x000000FF, (buff.src.deny_ip   & 0x0000FF00) >> 8,
                             (buff.src.deny_ip   & 0x00FF0000) >> 16, (buff.src.deny_ip   & 0xFF000000) >> 24);
                    ioctl(fd,LWFW_W,&buff.dest.deny_ip);
                     printf("dest ip: %d.%d.%d.%d\n",
                            buff.dest.deny_ip   & 0x000000FF, (buff.dest.deny_ip   & 0x0000FF00) >> 8,
                             (buff.dest.deny_ip   & 0x00FF0000) >> 16, (buff.dest.deny_ip   & 0xFF000000) >> 24);
                     ioctl(fd,LWFW_W,&buff.src.deny_port);
                     printf("source port: %d\n",buff.src.deny_port);
                     ioctl(fd,LWFW_W,&buff.dest.deny_port);
                     printf("dest port: %d\n",buff.dest.deny_port);
                     ioctl(fd,LWFW_W,&buff.type);
                     printf("type: %d\n",buff.type);
                     ioctl(fd,LWFW_W,&buff.dropped);
                     printf("dropped: %d\n",buff.dropped);
                     ioctl(fd,LWFW_W,&buff.start.hour);
                     printf("start hour: %d\n",buff.start.hour);
                     ioctl(fd,LWFW_W,&buff.end.hour);
                     printf("end hour:%d\n",buff.end.hour );
                     sig=ioctl(fd,LWFW_W,&buff.permit);
                     printf("ifpermit: %d\n\n",buff.permit);
                     buff.next=NULL;
                         if((fp=fopen("log","ab+"))==NULL){
                             printf("Cannot open file !");
                                return -1;
                        }
                            fwrite(&buff,sizeof(struct rules),1,fp);
                            fprintf(fphis,"source ip: %d.%d.%d.%d\n",
                            buff.src.deny_ip   & 0x000000FF, (buff.src.deny_ip   & 0x0000FF00) >> 8,
                             (buff.src.deny_ip   & 0x00FF0000) >> 16, (buff.src.deny_ip   & 0xFF000000) >> 24);
                     fprintf(fphis,"dest ip: %d.%d.%d.%d\n",
                            buff.dest.deny_ip   & 0x000000FF, (buff.dest.deny_ip   & 0x0000FF00) >> 8,
                             (buff.dest.deny_ip   & 0x00FF0000) >> 16, (buff.dest.deny_ip   & 0xFF000000) >> 24);
                     fprintf(fphis,"source port: %d\n",buff.src.deny_port);
                     fprintf(fphis,"dest port: %d\n",buff.dest.deny_port);
                     switch(buff.type){
                        case 0: fprintf(fphis,"type: IP\n");
                                    break;
                        case 1: fprintf(fphis,"type: TCP\n");
                                    break;
                        case 2:fprintf(fphis,"type: UDP\n");
                                    break;
                        case 3:fprintf(fphis, "type:ICMP\n" );
                                    break;
                        default:
                                    break;
                     }
                     fprintf(fphis,"dropped: %d\n",buff.dropped);
                     if(buff.start.hour!=0 || buff.end.hour!=0){
                            fprintf(fphis, "start hour: %d\n",buff.start.hour);
                            fprintf(fphis, "end hour: %d\n",buff.end.hour);                        
                     }
                     if(buff.permit)
                          fprintf(fphis,"permit\n");
                     time(&timep);
                    p = gmtime(&timep);
                      fprintf(fphis,"%-d-%d-%d\t", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday);
                     fprintf(fphis,"%s\t%d;%d;%d\n\n", wday[p->tm_wday], p->tm_hour+8, p->tm_min, p->tm_sec);
                    }while(!sig);
                    fclose(fp);
                    fclose(fphis);
                    break;
                case 'c':
                     if(ioctl(fd,LWFW_STATS_CLEAN) == -1)
                            printf("ioctl LWFW_STATS_CLEAN fail!\n");
                    return 0;
                case 't':
                    type = 1;
                    break;
                case 'u':
                    type = 2;
                    break;
                case 'i':
                    type = 3;
                    break;
                case 'p':
                    permit=1;
                    break;
                case 'r':
                    delete=1;
                    break;
                case 'l':
                    if((fp=fopen("log","r"))==NULL){
                             printf("Cannot open file !");
                                return -1;
                        }
                    if(feof(fp))    
                        printf("the file is empty\n");
                    num=fread(&infile,sizeof(struct rules),MAX,fp);
                    fclose(fp);
                    printf("num:%d\n",num );
                    for(i=0;i<num;i++){
                        printf("add rules...\n");
             if(ioctl(fd,LWFW_SET) == -1)
             {
                      perror("ioctl LWFW_SET fail!\n");
                      return -1;
            }
            if(ioctl(fd, LWFW_DENY_IP_SRC, infile[i].src.deny_ip) == -1)
             {
                printf("ioctl LWFW_DENY_IP_SRC fail\n");
                return -1;
            }
            if(ioctl(fd, LWFW_DENY_IP_DEST, infile[i].dest.deny_ip) == -1)
            {
                printf("ioctl LWFW_DENY_IP_DEST fail\n");
                return -1;
             } 
            if(ioctl(fd, LWFW_DENY_PORT_SRC, infile[i].src.deny_port) == -1)
            {
                printf("ioctl LWFW_DENY_PORT_SRC fail!\n");
                return -1;
            }  
            if(ioctl(fd, LWFW_DENY_PORT_DEST, infile[i].dest.deny_port) == -1)
            {
                printf("ioctl LWFW_DENY_PORT_DEST fail!\n");
                return -1;
            }
            if(ioctl(fd,LWFW_TYPE_SET,infile[i].type) == -1)
            {
                printf("ioctl LWFW_TYPE_SET fail!\n");
                return -1;
            }
            if(buff.permit)
                if(ioctl(fd,LWFW_PERMIT_SET) == -1)
            {
                printf("ioctl LWFW_PERMIT_SET fail!\n");
                return -1;
            }
                if(ioctl(fd,LWFW_TIME_START,infile[i].start.hour) == -1){
                    printf("ioctl LWFW_TIME_START fail!\n");
                    return -1;
                }
                if(ioctl(fd,LWFW_TIME_END,infile[i].end.hour) == -1){
                    printf("ioctl LWFW_TIME_END fail!\n");
                    return -1;
                }
            }
                break;
            case 'x':
            ioctl(fd,LWFW_TIME_START,strtol(optarg,&str,10));
            break;
        case 'y':
            ioctl(fd,LWFW_TIME_END,strtol(optarg,&str,10));
            break;
    default:
                    break;
            }
        }

       
        if(delete){
            if(ioctl(fd,LWFW_DELETE) == -1)
            {
                printf("ioctl LWFW_DELETE_SET fail!\n");
                return -1;
            }
        }
        if( flag[0]){
            if(ioctl(fd, LWFW_DENY_IP_SRC, inet_addr(deny_ip_src)) == -1)
             {
                printf("ioctl LWFW_DENY_IP_SRC fail\n");
                return -1;
            }
        }
        if( flag[1]){
            if(ioctl(fd, LWFW_DENY_IP_DEST, inet_addr(deny_ip_dest)) == -1)
            {
                printf("ioctl LWFW_DENY_IP_DEST fail\n");
                return -1;
             } 
        }
        if(flag[2]){
            if(ioctl(fd, LWFW_DENY_PORT_SRC, (unsigned int  )dps) == -1)
            {
                printf("ioctl LWFW_DENY_PORT_SRC fail!\n");
                return -1;
            }  
        }
        if(flag[3]){
            if(ioctl(fd, LWFW_DENY_PORT_DEST, (unsigned int )dpd) == -1)
            {
                printf("ioctl LWFW_DENY_PORT_DEST fail!\n");
                return -1;
            }
        }
        if(type&&!delete){
            if(ioctl(fd,LWFW_TYPE_SET,type) == -1)
            {
                printf("ioctl LWFW_TYPE_SET fail!\n");
                return -1;
            }
        }
        if(permit&&!delete){
            if(ioctl(fd,LWFW_PERMIT_SET) == -1)
            {
                printf("ioctl LWFW_PERMIT_SET fail!\n");
                return -1;
            }
        }
        close(fd);  
        return 0;
    }  