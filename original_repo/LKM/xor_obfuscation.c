#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/skbuff.h>

#define XOR_KEY_DEFAULT 0x5A  // Default XOR key for obfuscation
#define KEY_ROTATION_INTERVAL 10 // Rotate key every 10 seconds

static struct nf_hook_ops nfho;
static unsigned char xor_key = XOR_KEY_DEFAULT;
static struct proc_dir_entry *proc_entry;
static struct timer_list key_rotation_timer;

// XOR Encryption/Decryption
static void xor_encrypt_decrypt(unsigned char *data, unsigned int len) {
    unsigned int i;
    
    // Safety check for NULL data or zero length
    if (!data || len == 0)
        return;
        
    for (i = 0; i < len; i++) {
        data[i] ^= xor_key;
    }
}

// Hook function
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    unsigned char *payload;
    unsigned int payload_len = 0;
    unsigned int data_offset = 0;
    unsigned int headers_len = 0;
    
    // Basic validity checks
    if (!skb)
        return NF_ACCEPT;
    
    // Ensure we can access the IP header
    if (skb_headlen(skb) < sizeof(struct iphdr))
        return NF_ACCEPT;
        
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    // Calculate IP header length
    headers_len = iph->ihl * 4;
    
    // Check if this is TCP or UDP
    if (iph->protocol == IPPROTO_TCP) {
        // Make sure we can access the TCP header
        if (skb_headlen(skb) < headers_len + sizeof(struct tcphdr))
            return NF_ACCEPT;
            
        tcph = (struct tcphdr *)((unsigned char *)iph + headers_len);
        // Calculate TCP header length
        data_offset = headers_len + (tcph->doff * 4);
        
        // Calculate the payload length
        payload_len = ntohs(iph->tot_len) - data_offset;
        
        // Make sure we have a payload to encrypt
        if (payload_len <= 0)
            return NF_ACCEPT;
            
        // Ensure the entire packet is writable
        if (skb_ensure_writable(skb, ntohs(iph->tot_len)) < 0) {
            printk(KERN_WARNING "[Forensics] Failed to make packet writable\n");
            return NF_ACCEPT;
        }
        
        // Recalculate pointers after ensuring writable
        iph = ip_hdr(skb);
        tcph = (struct tcphdr *)((unsigned char *)iph + headers_len);
        
        // Get payload pointer
        payload = (unsigned char *)iph + data_offset;
        
    } else if (iph->protocol == IPPROTO_UDP) {
        // Make sure we can access the UDP header
        if (skb_headlen(skb) < headers_len + sizeof(struct udphdr))
            return NF_ACCEPT;
            
        udph = (struct udphdr *)((unsigned char *)iph + headers_len);
        
        // Calculate UDP data offset and payload length
        data_offset = headers_len + sizeof(struct udphdr);
        payload_len = ntohs(iph->tot_len) - data_offset;
        
        // Make sure we have a payload to encrypt
        if (payload_len <= 0)
            return NF_ACCEPT;
            
        // Ensure the entire packet is writable
        if (skb_ensure_writable(skb, ntohs(iph->tot_len)) < 0) {
            printk(KERN_WARNING "[Forensics] Failed to make packet writable\n");
            return NF_ACCEPT;
        }
        
        // Recalculate pointers after ensuring writable
        iph = ip_hdr(skb);
        udph = (struct udphdr *)((unsigned char *)iph + headers_len);
        
        // Get payload pointer
        payload = (unsigned char *)iph + data_offset;
        
    } else {
        // Not a TCP or UDP packet
        return NF_ACCEPT;
    }
    
    // Check the total packet length against the skb length to ensure we have enough data
    if (ntohs(iph->tot_len) > skb->len) {
        printk(KERN_WARNING "[Forensics] Packet length mismatch\n");
        return NF_ACCEPT;
    }

    // Now encrypt/decrypt the payload
    if (payload_len > 0 && payload_len <= 65535) {  // Sanity check on payload length
        // Perform the XOR operation
        xor_encrypt_decrypt(payload, payload_len);
        
        // Set the checksum to CHECKSUM_NONE to force recalculation
        skb->ip_summed = CHECKSUM_NONE;
        
        printk(KERN_INFO "[Forensics] Obfuscated packet from source: %pI4, destination: %pI4, protocol: %d, payload_len: %u\n",
               &iph->saddr, &iph->daddr, iph->protocol, payload_len);
    }
    
    return NF_ACCEPT;
}

// Proc file write function
static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char buf[4];
    if (count > 3) return -EINVAL;
    if (copy_from_user(buf, buffer, count)) return -EFAULT;
    buf[count] = '\0';
    if (kstrtou8(buf, 16, &xor_key)) return -EINVAL;
    printk(KERN_INFO "[Forensics] XOR key manually set to: 0x%02X\n", xor_key);
    return count;
}

// Proc file read function
static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *pos) {
    char buf[4];
    int len = snprintf(buf, sizeof(buf), "%02X\n", xor_key);
    return simple_read_from_buffer(buffer, count, pos, buf, len);
}

static const struct proc_ops proc_fops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

// Key rotation function
static void rotate_key(struct timer_list *t) {
    xor_key = (xor_key + 17) % 256;  // Simple rotation logic
    printk(KERN_INFO "[Forensics] XOR key rotated to: 0x%02X\n", xor_key);
    mod_timer(&key_rotation_timer, jiffies + KEY_ROTATION_INTERVAL * HZ);
}

static int __init xor_obfuscation_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    
    if (nf_register_net_hook(&init_net, &nfho)) {
        printk(KERN_ERR "[Forensics] Failed to register netfilter hook\n");
        return -EINVAL;
    }
    
    proc_entry = proc_create("xor_key", 0666, NULL, &proc_fops);
    if (!proc_entry) {
        nf_unregister_net_hook(&init_net, &nfho);
        printk(KERN_ERR "[Forensics] Failed to create proc entry\n");
        return -ENOMEM;
    }
    
    timer_setup(&key_rotation_timer, rotate_key, 0);
    mod_timer(&key_rotation_timer, jiffies + KEY_ROTATION_INTERVAL * HZ);
    
    printk(KERN_INFO "[Forensics] XOR packet obfuscation module loaded with key: 0x%02X\n", xor_key);
    return 0;
}

static void __exit xor_obfuscation_exit(void) {
    del_timer(&key_rotation_timer);
    nf_unregister_net_hook(&init_net, &nfho);
    proc_remove(proc_entry);
    printk(KERN_INFO "[Forensics] XOR packet obfuscation module unloaded.\n");
}

module_init(xor_obfuscation_init);
module_exit(xor_obfuscation_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyber Forensics Research");
MODULE_DESCRIPTION("A kernel module that obfuscates network packets using XOR encryption with dynamic key control, logging, and automatic key rotation.");