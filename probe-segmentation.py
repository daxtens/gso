from bcc import BPF

bpf_text = """ 
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

// todo , show devs
int kprobe____skb_gso_segment(struct pt_regs *ctx, struct sk_buff *skb)
{
	bpf_trace_printk("  __skb_gso_segment:  in: skb = %p, len = %d\\n", skb, skb->len);
	return 0;
};

int kprobe__skb_mac_gso_segment(struct pt_regs *ctx, struct sk_buff *skb)
{
	bpf_trace_printk("skb_mac_gso_segment:  in: skb = %p, len = %d, proto = %x\\n",
                         skb, skb->len, skb->protocol);
	return 0;
};

int kprobe__inet_gso_segment(struct pt_regs *ctx, struct sk_buff *skb)
{
        // get the next proto inside the ipv4 header
	bpf_trace_printk("   inet_gso_segment:  in: skb = %p, len = %d\\n", skb, skb->len);
	return 0;
};

int kprobe__udp4_ufo_fragment(struct pt_regs *ctx, struct sk_buff *skb)
{
	bpf_trace_printk("  udp4_ufo_fragment:  in: skb = %p, len = %d\\n", skb, skb->len);
	return 0;
};

int kretprobe__udp4_ufo_fragment(struct pt_regs *ctx)
{
        struct sk_buff *skb = (struct sk_buff*)PT_REGS_RC(ctx);
	struct sk_buff s = {};

	//bpf_probe_read(&sh, sizeof(sh), skb->head + skb->end);
	//len = skb->len;

        if (skb == NULL) {
                bpf_trace_printk("  udp4_ufo_fragment: out: NULL (no segmentation performed)\\n");
                return 0;
        }

        // we can't loop, so just unroll the first 10
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("  udp4_ufo_fragment: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
        bpf_trace_printk("           next skb: <continues>\\n");

	return 0;
};


// todo - actual segmentation routine

int kretprobe____skb_gso_segment(struct pt_regs *ctx)
{
        struct sk_buff *skb = (struct sk_buff*)PT_REGS_RC(ctx);
	struct sk_buff s = {};
	//struct skb_shared_info sh = {};
	unsigned int len;
unsigned int i;

	//bpf_probe_read(&sh, sizeof(sh), skb->head + skb->end);
	//len = skb->len;

        if (skb == NULL) {
                bpf_trace_printk("  __skb_gso_segment: out: NULL (no segmentation performed)\\n");
                return 0;
        }

        // we can't loop, so just unroll the first 10
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("  __skb_gso_segment: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
	bpf_probe_read(&s, sizeof(s), skb);
        bpf_trace_printk("           next skb: out: skb = %p, len = %u\\n", skb, s.len);
        skb = s.next;
        if (!skb)
                return 0;
        bpf_trace_printk("           next skb: <continues>\\n");

	return 0;
};
"""

# 2. Build and Inject program
b = BPF(text=bpf_text)
print("compiled and inserted OK")
# 3. Print debug output
while True:
    print b.trace_readline()
