from bcc import BPF
import operator
import plotly
import plotly.graph_objs as go

# define BPF program
prog = """
#include <linux/sched.h>
#include <linux/spinlock_types.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u32 tid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    u64 lock;
    u64 lock_time;
    u64 present_time;
    u64 diff;
    u32 lock_count;
};

BPF_HASH(locks, raw_spinlock_t*, struct data_t);
BPF_HISTOGRAM(locks_hist, raw_spinlock_t*, 64);

BPF_PERF_OUTPUT(events);

int lock(struct pt_regs *ctx, raw_spinlock_t *lock) {
    struct data_t data = {};
    struct data_t *data_ptr;
    data_ptr = locks.lookup(&lock);
    if(data_ptr)
    {
        data_ptr->ts = bpf_ktime_get_ns();
        data_ptr->lock_count += 1;
    }
    else
    {
        //u64 lock1 = PT_REGS_PARM1(ctx);
        data.pid = bpf_get_current_pid_tgid();
        data.tid = bpf_get_current_pid_tgid() >> 32;
        data.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.lock = (u64)lock;
        //events.perf_submit(ctx, &data, sizeof(data));
        data.lock_count = 1;
        locks.insert(&lock, &data);
    }
    return 0;
}

int release(struct pt_regs *ctx, raw_spinlock_t *lock) {
    u64 present = bpf_ktime_get_ns();
    struct data_t *data;
    data = locks.lookup(&lock);
    //bpf_trace_printk("%d\\n", data);
    if(data)
    {
        data->lock_time += (present - data->ts);
        data->present_time = present;
        data->diff = present - data->ts;
        events.perf_submit(ctx, data, sizeof(struct data_t));
        //data->ts = 0; 
        //locks.update(&lock, data);
        locks_hist.increment(lock);
        //kstack();
    }
    return 0;
}
"""

#Graph generation code
def generate_histogram(events):
    trace0 = go.Bar(
        x=[i for i in range(len(events))],
        y=[event['lock_time'] for event in events],
        text=["Lock address:%d<br>Command:%s<br>Lock operation count:%d<br>Locking time:%d<br>"
        %(event['lock'], event['comm'], event['lock_count'], event['lock_time']) for event in events],
        marker=dict(
            color='rgb(158,202,225)',
            line=dict(
                color='rgb(255, 127, 14)',
                #width=1.0,
            )
        ),
        opacity=0.6
    )

    plotly.offline.plot({
        "data": [trace0],
        "layout": go.Layout(title="Write locks in kernel")
    }, auto_open=True)
    print plotly.offline.plot([trace0], include_plotlyjs=False, output_type='div')


# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="_raw_write_lock", fn_name="lock")
b.attach_kretprobe(event="_raw_write_lock", fn_name="release")
events = {}
# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "LOCKTIME"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start))  / 1000000000
    print("%-18.9f %-16s %-6d %-6d %-6d %-6f     %-15f %-6d" % (time_s, event.comm, event.pid, event.tid,
     event.lock, (float(event.present_time - start))  / 1000000000, event.lock_time, event.diff))
    event_dict = {  'ts':event.ts,
                    'lock':event.lock,
                    'present_time':event.present_time,
                    'lock_time':event.lock_time,
                    'diff': event.diff,
                    'tid':event.tid,
                    'pid':event.pid,
                    'comm':event.comm,
                    'lock_count':event.lock_count
                    }
    #events.append(event_dict)
    # found = 0
    # for key in events.keys:
    #     if events[key]['lock'] == event_dict['lock']:
    #         found = 1
    #         event[key] = event_dict
    # if not found:
    events[event_dict['lock']] = event_dict

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
try:
    while 1:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    min_lock_time = 100000000000
    for key, event in events.iteritems():
        if event['diff'] < min_lock_time:
            min_lock_time = event['diff']
    print "\nMinimum lock time is : %d\n" % min_lock_time
    #b["locks_hist"].print_log2_hist("lock")
    event_list = sorted(events.values(), key=lambda kv: kv['lock_time'], reverse=True)
    # event_list.sort(key=lambda kv: kv['lock_time'], reverse=True)
    generate_histogram(event_list[:10])

