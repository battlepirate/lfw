/* lwfw.c */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/rtc.h> 
#include <linux/time.h>

#include <asm/uaccess.h>
#include <asm/errno.h>

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/device.h>
#include "lwfw.h"

static struct cdev *cdev;
static dev_t devno;
struct class *my_class;

/* Local function prototypes */
static int set_ip_rule_src(unsigned int ip);
static int set_ip_rule_dest(unsigned int ip);
static int set_port_rule_src(unsigned int port);
static int set_port_rule_dest(unsigned int port);
static int check_ip_packet(struct sk_buff *skb);
static int check_tcp_packet(struct sk_buff *skb);
static int check_udp_packet(struct sk_buff *skb);
static int check_icmp_packet(struct sk_buff *skb);
static int check_time(struct sk_buff *skb,struct rules *p);
static int copy_stats(struct lwfw_stats *statbuff);

static int scroll=0;
static int copy_rules(unsigned int *tmp);

/* Some  prototypes to be used by lwfw_fops below. */
static long lwfw_ioctl(struct file *file,
              unsigned int cmd, unsigned long arg);
static int lwfw_open(struct inode *inode, struct file *file);
static int lwfw_release(struct inode *inode, struct file *file);

/* Various flags used by the module */
/* This flag makes sure that only one instance of the lwfw device
* can be in use at any one time. */
static int lwfw_ctrl_in_use = 0;
/* This flag marks whether LWFW should actually attempt rule checking.
* If this is zero then LWFW automatically allows all packets. */
static int active = 0;
static int delete=0;

/* Specifies options for the LWFW module */
/*static unsigned int lwfw_options = (LWFW_IF_DENY_ACTIVE
                    | LWFW_IP_DENY_ACTIVE
                    | LWFW_PORT_DENY_ACTIVE);*/

/* This struct will describe our hook procedure. */
struct nf_hook_ops nfkiller_pre;
struct nf_hook_ops nfkiller_out;

/* Module statistics structure */
static struct lwfw_stats lwfw_statistics = {0, 0};

/* Actual rule 'definitions'. */
/* TODO: One day LWFW might actually support many simultaneous rules.
* Just as soon as I figure out the list_head mechanism... */
//static char *deny_if = NULL;
/*static unsigned int deny_ip = 0x00000000; 
static unsigned short deny_port = 0x0000; */

static struct rules *head = NULL;
static struct rules *tmp =NULL;
/*
* This is the interface device's file_operations structure
*/
struct file_operations lwfw_fops = {
     //.ioctl=lwfw_ioctl,
     .unlocked_ioctl=lwfw_ioctl,
     .open=lwfw_open,
     .release=lwfw_release,
};

/*
* This is the function that will be called by the hook
*/
unsigned int lwfw_hookfn(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *))
{
   unsigned int ret = NF_ACCEPT;
  // printk("%x\n",deny_ip);
   if (!active || !head)
     return NF_ACCEPT;
   
   lwfw_statistics.total_seen++;
   /* Check the interface rule first */
/*if (head && DENY_IF_ACTIVE) {
        if (strcmp(in->name, deny_if) == 0) { 
            lwfw_statistics.total_dropped++;
             return NF_DROP;
        }
      }*/
   
   /* Check the IP address rule */
     ret = check_ip_packet(skb);
     if (ret != NF_ACCEPT) 
             return ret;

        switch(ip_hdr(skb)->protocol){
            case IPPROTO_TCP:
                ret = check_tcp_packet(skb);
                if (ret != NF_ACCEPT) 
                      return ret;
                break;
            case  IPPROTO_UDP:
                ret = check_udp_packet(skb);
                if (ret != NF_ACCEPT) 
                    return ret;
                break;
            case IPPROTO_ICMP:
                    ret = check_icmp_packet(skb);
                if (ret != NF_ACCEPT) 
                      return ret;
                  break;
            default:
                    break;
              }

   return NF_ACCEPT; /* We are happy to keep the packet */
}

/* Function to copy the LWFW statistics to a userspace buffer */
static int copy_stats(struct lwfw_stats *statbuff)
{
   NULL_CHECK(statbuff);
   copy_to_user(statbuff, &lwfw_statistics,sizeof(struct lwfw_stats));
   return 0;
}

static int copy_rules(unsigned int *srcip)
{
    NULL_CHECK(srcip);

    if(tmp==NULL){
        printk("NO  rules!\n");
        return 1;
    }

    if(head==NULL){
        printk("NO  rules!\n");
        return 1;
    }
    switch(scroll){
        case 0:
            copy_to_user(srcip,&tmp->src.deny_ip,sizeof(unsigned int));
            scroll++;
            return 0;
        case 1:
            copy_to_user(srcip,&tmp->dest.deny_ip,sizeof(unsigned int));
            scroll++;
            return 0;
        case 2:
            copy_to_user(srcip,&tmp->src.deny_port,sizeof(unsigned int));
            scroll++;
            return 0;
         case 3:
            copy_to_user(srcip,&tmp->dest.deny_port,sizeof(unsigned int));
            scroll++;
            return 0;
        case 4:
            copy_to_user(srcip,&tmp->type,sizeof(unsigned int));
            scroll++;
            return 0;
        case 5:
            copy_to_user(srcip,&tmp->dropped,sizeof(unsigned int));
            scroll++;
            return 0;
        case 6:
            copy_to_user(srcip,&tmp->start.hour,sizeof(unsigned int));
            scroll++;
            return 0;
        case 7:
            copy_to_user(srcip,&tmp->end.hour,sizeof(unsigned int));
            scroll++;
            return 0;
        case 8:
            copy_to_user(srcip,&tmp->permit,sizeof(unsigned int));
            scroll=0;
            tmp=tmp->next;
            if(tmp==NULL) {
                tmp=head;
                return 1;
            }
            else
                return 0;
    }
    
    return 0;
}
static int check_icmp_packet(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct rules *p;

     iph = ip_hdr(skb);
   if (!skb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;
   for(p=head;p!=NULL; p=p->next){
   if (p->type == 3){
        // if(iph->saddr == p->src.deny_ip || iph->daddr == p->dest.deny_ip){
                if(p->permit){
                    printk("rule permit \n");
                    return NF_ACCEPT;
                }
                else if(p->start.hour != 0 || p->end.hour != 0)
                    return check_time(skb,p);
                else
                    lwfw_statistics.total_dropped++;
                    p->dropped++;
                     return NF_DROP;
                // }
            }  
        }

   return NF_ACCEPT;
}

static int check_udp_packet(struct sk_buff *skb)
{
    struct udphdr *thead = udp_hdr(skb);
    struct iphdr *iph;
    struct rules *p;

     iph = ip_hdr(skb);
   if (!skb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;

   for(p=head;p!=NULL; p=p->next)
   if (p->type == 2){
        /* Now check the destination port */
        if(p->src.deny_ip==0 && p->dest.deny_ip==0 ){
            if (ntohs(thead->source) == p->src.deny_port ||ntohs(thead->source) == p->dest.deny_port ||(p->src.deny_port==0 && p->src.deny_port==0)) {         /* Update statistics */
                    if(p->permit)
                            return NF_ACCEPT;
                     if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                      p->dropped++;
                     lwfw_statistics.total_dropped++;
                     return NF_DROP;
                  }
        }
        else if(iph->saddr == p->src.deny_ip || iph->daddr == p->dest.deny_ip){
                if(p->src.deny_port==0 && p->dest.deny_port==0){
                    if(p->permit)
                        return NF_ACCEPT;
                    if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                   p->dropped++;
                     lwfw_statistics.total_dropped++;
                    return NF_DROP;
                }
                if (ntohs(thead->source) == p->src.deny_port ||ntohs(thead->source) == p->dest.deny_port ){         /* Update statistics */
                    if(p->permit)
                            return NF_ACCEPT;
                  if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                p->dropped++;
                     lwfw_statistics.total_dropped++;
                     return NF_DROP;
                  }
            }  
        }

   return NF_ACCEPT;
}

static int check_tcp_packet(struct sk_buff *skb)
{
   struct tcphdr *thead;
   struct iphdr *iph;
   struct rules *p;

   iph = ip_hdr(skb);
   if (!skb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;

   /* Be sure this is a TCP packet first */
   for(p=head;p!=NULL; p=p->next)
   if (p->type == 1){
         thead = (struct tcphdr *)(skb->data + (iph->ihl * 4));
        printk("thead->source:%d\n",ntohs(thead->source));
        printk("p->src.deny_port: %d\n",p->src.deny_port);
        printk("p->dest.deny_port:%d\n",p->dest.deny_port);
        if(p->src.deny_ip==0 && p->dest.deny_ip==0 ){
            if (ntohs(thead->source) == p->src.deny_port ||ntohs(thead->source) == p->dest.deny_port ){         /* Update statistics */
                    if(p->permit)
                            return NF_ACCEPT;
                 if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                     p->dropped++;
                     lwfw_statistics.total_dropped++;
                     return NF_DROP;
                  }
        }
        else if(iph->saddr == p->src.deny_ip || iph->daddr == p->dest.deny_ip){
                if(p->src.deny_port==0 && p->dest.deny_port==0){
                     if(p->permit)
                            return NF_ACCEPT;
                        if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                     p->dropped++;
                     lwfw_statistics.total_dropped++;
                    return NF_DROP;
                }
                if (ntohs(thead->source) == p->src.deny_port||  ntohs(thead->dest) == p->dest.deny_port ){         /* Update statistics */         
                      if(p->permit)
                            return NF_ACCEPT;
                        if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                     p->dropped++;
                     lwfw_statistics.total_dropped++;
                     return NF_DROP;
                  }
            }  
        }

   return NF_ACCEPT;
}

static int check_ip_packet(struct sk_buff *skb)
{
   struct iphdr *iph;
   struct sk_buff *sb = skb;
   struct rules *p;

   iph = ip_hdr(skb);
   /* We don't want any NULL pointers in the chain to the IP header. */
   if (!sb ) return NF_ACCEPT;
   if (!(iph)) return NF_ACCEPT;

      for(p=head; p!=NULL; p=p->next){
           //printk("now check ip...\n");
         if(p->type == 0){
          if (iph->saddr == p->src.deny_ip || iph->daddr == p->dest.deny_ip){
              if(p->permit)
                               return NF_ACCEPT;
                if(p->start.hour != 0 || p->end.hour != 0)
                        return check_time(skb,p);
                p->dropped++;
                lwfw_statistics.total_dropped++;
                 return NF_DROP;
             }
            }
        }

       return NF_ACCEPT;
}

static int check_time(struct sk_buff *skb,struct rules *p)
{
    struct rtc_time tm;
    struct timex txc;
    NULL_CHECK(skb);

    tm = rtc_ktime_to_tm(skb->tstamp);

    printk("CURRENT time :%d-%d-%d %d:%d:%d\n",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour+8,tm.tm_min,tm.tm_sec); 

    do_gettimeofday(&(txc.time));

        if((tm.tm_hour+8)<=p->end.hour&&(tm.tm_hour+8)>=p->start.hour)
    {
        if(p->permit)
            return NF_ACCEPT;
        printk("time in the rule\n");
        lwfw_statistics.total_dropped++;
        p->dropped++;
        return 0;
        }
        printk("time is not in the rule.\n");
        return NF_ACCEPT;
}

static int set_ip_rule_src(unsigned int ip)
{
   struct rules *p,*q;
   if(delete){
   if(head->src.deny_ip==ip){
        p=head;
        head=head->next;
        kfree(p);
        printk("delete rule!\n" );
        delete = 0;
        return 0;
   }
   for(p=head,q=p->next;p!=NULL;p=p->next){
        if(q->src.deny_ip==ip){
            p->next=q->next;
            kfree(q);
            printk("delete rule!\n" );
            delete = 0;
            return 0;
        }
     }
    }

   head->src.deny_ip = ip;
   
   printk("LWFW: Set to deny from IP address: %d.%d.%d.%d\n",
      ip & 0x000000FF, (ip & 0x0000FF00) >> 8,
      (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
   
   return 0;
}

static int set_ip_rule_dest(unsigned int ip)
{
     struct rules *p,*q;
   if(delete){
   if(head->dest.deny_ip==ip){
        p=head;
        head=head->next;
        kfree(p);
        printk("delete rule!\n" );
        delete = 0;
        return 0;
   }
   for(p=head,q=p->next;p!=NULL;p=p->next){
        if(q->dest.deny_ip==ip){
            p->next=q->next;
            kfree(q);
            printk("delete rule!\n" );
            delete = 0;
            return 0;
        }
     }
    }

   head->dest.deny_ip = ip;
   
   printk("LWFW: Set to deny to IP address: %d.%d.%d.%d\n",
      ip & 0x000000FF, (ip & 0x0000FF00) >> 8,
      (ip & 0x00FF0000) >> 16, (ip & 0xFF000000) >> 24);
   
   return 0;
}

static int set_port_rule_src(unsigned int port)
{
      struct rules *p,*q;
   if(delete){
 if(head->src.deny_port==port){
        p=head;
        head=head->next;
        kfree(p);
        printk("delete rule!\n" );
        delete = 0;
        return 0;
   }
   for(p=head,q=p->next;p!=NULL;p=p->next){
        if(q->src.deny_port==port){
            p->next=q->next;
            kfree(q);
            printk("delete rule!\n" );
            delete = 0;
            return 0;
        }
     }
    }

   head->src.deny_port = port;
   
   printk("LWFW: Set to deny  from port: %d\n",
      head->src.deny_port);
      
   return 0;
}

static int set_port_rule_dest(unsigned int port)
{
      struct rules *p,*q;
   if(delete){
   if(head->src.deny_port==port){
        p=head;
        head=head->next;
        kfree(p);
        printk("delete rule!\n" );
        delete = 0;
        return 0;
   }
   for(p=head,q=p->next;p!=NULL;p=p->next){
        if(q->dest.deny_port==port){
            p->next=q->next;
            kfree(q);
            printk("delete rule!\n" );
            delete = 0;
            return 0;
        }
     }
    }
   head->dest.deny_port =  port;
   
   printk("LWFW: Set to deny  to port: %d\n",
     head->dest.deny_port);
      
   return 0;
}


/*********************************************/
/*
* File operations functions for control device
*/
static long lwfw_ioctl(struct file *file,
              unsigned int cmd, unsigned long arg)
{
   int ret = 0;
   struct rules *p = NULL;
   
   switch (cmd) {
    case LWFW_GET_VERS:
      return LWFW_VERS;
    case LWFW_ACTIVATE: {
       active = 1;
       printk("LWFW: Activated.\n");
       if (!head) {
      printk("LWFW: No deny options set.\n");
       }
       break;
    }
    case LWFW_DEACTIVATE: {
       active ^= active;
       printk("LWFW: Deactivated.\n");
       break;
    }
    case LWFW_GET_STATS: {
       ret = copy_stats((struct lwfw_stats *)arg);
       break;
    }
    case LWFW_SET:{
      if(head == NULL){
        head = (struct rules*)kmalloc(sizeof(struct rules),GFP_KERNEL);
        head->dropped = 0;
        head->type = 0;
        head->permit = 0;
        head->src.deny_ip = 0;
        head->src.deny_port = 0;
        head->dest.deny_ip = 0;
        head->dest.deny_port = 0;
        head->start.hour = 0;
        head->end.hour = 0;
        head->next = NULL;
        tmp=head;
      }
      else{
        p = (struct rules*)kmalloc(sizeof(struct rules),GFP_KERNEL);
        p->dropped = 0;
        p->type = 0;
        p->next = head;
        p->permit = 0;
        p->src.deny_ip = 0;
        p->src.deny_port = 0;
        p->dest.deny_ip = 0;
        p->dest.deny_port = 0;
        p->start.hour = 0;
        p->end.hour = 0;
        head = p;
        tmp=head;
      }
      printk("LWFW: set rules!\n");
      break;
    }
    case LWFW_DELETE:{
        delete=1;
        break;
    }
    case LWFW_DENY_IP_SRC: {
       ret = set_ip_rule_src((unsigned int)arg);
       break;
    }
    case LWFW_DENY_IP_DEST:{
      ret = set_ip_rule_dest((unsigned int)arg);
      break;
    }
    case LWFW_DENY_PORT_SRC: {
       ret = set_port_rule_src((unsigned int)arg);
       break;
    }
    case LWFW_DENY_PORT_DEST: {
       ret = set_port_rule_dest((unsigned int)arg);
       break;
    }
    case LWFW_STATS_CLEAN:{
        lwfw_statistics.total_dropped=0;
        lwfw_statistics.total_seen=0;
        while(head!=NULL){
                p=head;
                head=head->next;
                kfree(p);           
        }
        ret = 0;
        break;
    }
    case LWFW_TYPE_SET:{
        head->type=(unsigned int )arg;
        ret = 0;
        break;
    }
    case LWFW_PERMIT_SET:{
        printk("set permit\n" );
        head->permit=1;
        ret = 0;
        break;
    }
    case LWFW_W:{
        ret = copy_rules((unsigned int  *)arg);
       break;
    }
    case LWFW_FILE_READ:{
        p = kmalloc(sizeof(struct rules),GFP_KERNEL);
        copy_from_user(p,(void*)arg,sizeof(struct rules));
        if(head == NULL){
            head=p;
            p->next=NULL;
        }
        else
        {
            p->next=head;
            head=p;
        }
        break;
    }
    case LWFW_TIME_START:
        head->start.hour = (unsigned)arg;
        break;
    case LWFW_TIME_END:
        head->end.hour = (unsigned)arg;
        break;
    default:
      ret = -EBADRQC;
   };
   
   return ret;
}

/* Called whenever open() is called on the device file */
static int lwfw_open(struct inode *inode, struct file *file)
{
   if (lwfw_ctrl_in_use) {
      return -EBUSY;
   } else {
   // MOD_INC_USE_COUNT;

      lwfw_ctrl_in_use++;
      return 0;
   }
   return 0;
}

/* Called whenever close() is called on the device file */
static int lwfw_release(struct inode *inode, struct file *file)
{
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;
 // MOD_DEC_USE_COUNT;

   return 0;
}

/*********************************************/
/*
* Module initialisation and cleanup follow...
*/
int lwfw_init(void)
{
   /* 注册设备 /dev/lwfw */

    cdev = cdev_alloc();    
    if(cdev == NULL)
        return -1;
    if(alloc_chrdev_region(&devno,0,10,"lwfw")){
    printk("register char dev error\n");
    return -1;
    }
    cdev_init(cdev,&lwfw_fops);
    if(cdev_add(cdev,devno,1))
    {
        printk("add the cedev error\n");
    }
    my_class = class_create(THIS_MODULE,"test_class");
    if(IS_ERR(my_class))
    {
        printk("Err:failed in creating class.\n");
        return -1;
    }
    device_create(my_class,NULL,devno,NULL,"lwfw");
   
   /* Make sure the usage marker for the control device is cleared */
   lwfw_ctrl_in_use ^= lwfw_ctrl_in_use;

//注册hook
   printk("LWFW: Control device successfully registered.\n");
   nfkiller_pre.hook = (nf_hookfn*)lwfw_hookfn; 
   nfkiller_pre.hooknum = NF_INET_PRE_ROUTING; /* First stage hook */
   nfkiller_pre.pf = PF_INET; /* IPV4 protocol hook */
   nfkiller_pre.priority = NF_IP_PRI_FIRST; /* Hook to come first */
   
   nf_register_hook(&nfkiller_pre);
   
   nfkiller_out.hook = (nf_hookfn*)lwfw_hookfn; 
   nfkiller_out.hooknum = NF_INET_LOCAL_OUT; /* First stage hook */
   nfkiller_out.pf = PF_INET; /* IPV4 protocol hook */
   nfkiller_out.priority = NF_IP_PRI_FIRST; /* Hook to local out */

   //nf_register_hook(&nfkiller_out);

// printk("LWFW: Network hooks successfully installed.\n");

   
   printk("LWFW: Module installation successful.\n");
   return 0;
}

void lwfw_exit(void)
{
    struct rules*p;
   nf_unregister_hook(&nfkiller_pre);
   //nf_unregister_hook(&nfkiller_out);

  unregister_chrdev_region(devno, 1);
  cdev_del(cdev);
  device_destroy(my_class,devno);
  class_destroy(my_class);
  printk("LWFW: Removal of module failed!\n");
   

   /* If anything was allocated for the deny rules, free it here */
   for(p=head;p!=NULL;p=p->next){
        head=p->next;
        kfree(p);
   }
   
   printk("LWFW: Removal of module successful.\n");
}
module_init(lwfw_init);
module_exit(lwfw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux lwfw");
