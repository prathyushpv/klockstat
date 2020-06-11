from __future__ import print_function

from bcc import BPF
import operator
import errno
from jinja2 import Environment, FileSystemLoader
import os
import datetime
import argparse
import numpy as np

# define BPF program

locks = [
    {
       'id': 1,
       'name': 'write_lock',
       'title': 'Read/Write Lock',
       'lock_func': '_raw_write_lock'
    },
    {
       'id': 2,
       'name': 'read_lock',
       'title': 'Read/Write Lock',
       'lock_func': '_raw_read_lock'
    },
     {
         'id': 3,
         'name': 'mutex',
         'title': 'Mutex',
         'lock_func': 'mutex_lock'
     },

    {
       'id': 3,
       'name': 'write_lock_sema',
       'title': 'Read/Write Semaphore',
       'lock_func': 'up_write'
    },
    {
       'id': 4,
       'name': 'read_lock_s',
       'title': 'Read/Write Semaphore',
       'lock_func': 'up_read'
    },
]

prog_header = """
#include <linux/sched.h>
#include <linux/spinlock_types.h>

// define struct for key

struct key_t {
    u64 pid;
    raw_spinlock_t* lock;
};
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
    u64 stack_id;
    u32 lock_count;
    u32 type;
};

//BPF_HASH(locks, struct key_t, struct data_t, 102400);
// todo multiple stack traces
BPF_STACK_TRACE(stack_traces, 102400);

"""
lock_func = """
BPF_PERF_OUTPUT(_NAME_);
BPF_HASH(map__NAME_, struct key_t, struct data_t, 102400);

int lock__NAME_(struct pt_regs *ctx, raw_spinlock_t *lock) {

    u32 current_pid = bpf_get_current_pid_tgid();
    if(current_pid == CUR_PID)
        return 0;
        
    struct data_t data = {};
    struct key_t key = {bpf_get_current_pid_tgid(), lock};
    struct data_t *data_ptr;
    data_ptr = map__NAME_.lookup(&key);
    if(data_ptr)
    {
        data_ptr->ts = bpf_ktime_get_ns();
        data_ptr->lock_count += 1;
        data_ptr->stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    }
    else
    {
        data.pid = bpf_get_current_pid_tgid();
        data.tid = bpf_get_current_pid_tgid() >> 32;
        data.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.lock = (u64)lock;
        data.lock_count = 1;
        data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
        map__NAME_.insert(&key, &data);
    }
    return 0;
}

int release__NAME_(struct pt_regs *ctx, raw_spinlock_t *lock) {
    u64 present = bpf_ktime_get_ns();
    
    u32 current_pid = bpf_get_current_pid_tgid();
    if(current_pid == CUR_PID)
        return 0;
        
    struct data_t *data;
    struct key_t key = {bpf_get_current_pid_tgid(), lock};
    data = map__NAME_.lookup(&key);
    if(data)
    {
        data->lock_time += (present - data->ts);
        data->present_time = present;
        data->diff = present - data->ts;
        data->type = _ID_;
        _NAME_.perf_submit(ctx, data, sizeof(struct data_t));
        //map__NAME_.delete(&key);
    }
    return 0;
}
"""


# Graph generation code
# def generate_histogram(events):
#     trace0 = go.Bar(
#         x=[i for i in range(len(events))],
#         y=[event['lock_time'] for event in events],
#         text=["Lock address:%d<br>Command:%s<br>Lock operation count:%d<br>Locking time:%d<br>"
#               % (event['lock'], event['comm'], event['lock_count'], event['lock_time']) for event in events],
#         marker=dict(
#             color='rgb(158,202,225)',
#             line=dict(
#                 color='rgb(255, 127, 14)',
#                 # width=1.0,
#             )
#         ),
#         opacity=0.6
#     )
#
#     plotly.offline.plot({
#         "data": [trace0],
#         "layout": go.Layout(title="Write locks in kernel")
#     }, auto_open=True)
#     print(plotly.offline.plot([trace0], include_plotlyjs=False, output_type='div'))


def generate_report(event_list):
    for event in event_list:
        for lock in locks:
            if event['type'] == lock['id']:
                event['type_name'] = lock['title']
                break

    report_data = {}
    report_data['all_chart'] = event_list[:10]
    lock_times = {'write_lock': 100}
    report_data['lock_times'] = lock_times
    report_data['all_table'] = event_list[:20]

    locks_report = []
    for lock in locks:
        if lock['id'] == 2:
            continue
        if lock['id'] == 4:
            continue
        lock_report = dict(lock)
        lock_report['events'] = []
        lock_report['time'] = 0
        for event in event_list:
            if event['type'] == lock['id']:
                event['stack_list'] = [[trace, details['count'], details['time'], round(float(details['time'])/event['lock_time']*100, 2)] 
                                        for trace, details in event['stack_traces'].items()]
                event['stack_list'] = sorted(event['stack_list'], key=lambda kv: kv[2], reverse=True)
                lock_report['events'].append(event)
                lock_report['time'] += event['lock_time']
            # print(event['stack_traces'])
        lock_report['events'] = lock_report['events'][:20]
        locks_report.append(lock_report)
    report_data['locks_report'] = locks_report

    # Generating box plot
    box_data = {}
    lock_times = {}
    for lock in locks:
        lock_times[lock['id']] = []
    for event in event_list:
        lock_times[event['type']].append(event['lock_time'])
    for lock in locks:
        lock_times_list = np.array(lock_times[lock['id']])
        box_data[lock['name']] = [np.min(lock_times_list),
                                  np.percentile(lock_times_list, 25),
                                  np.percentile(lock_times_list, 50),
                                  np.percentile(lock_times_list, 75),
                                  np.percentile(lock_times_list, 90),
                                  ]
    report_data['box_data'] = box_data

    # print(locks_report)

    env = Environment(loader=FileSystemLoader('template'))
    with open("lockstat_report.html", "w") as out_file:
        template = env.get_template('report.html')
        output_from_parsed_template = template.render(data=report_data)
        out_file.write(output_from_parsed_template.encode('utf8'))


def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not availible,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)


def print_stack(stack_id):
    if stack_id_err(stack_id):
        print("    [Missed Stack]" )
        return
    stack = list(b.get_table("stack_traces").walk(stack_id))
    for addr in stack:
        print("        ", end="")
        print("%s" % (b.sym(addr, -1, show_module=True, show_offset=True)))


def get_stack(stack_id):
    if stack_id_err(stack_id):
        return "[Missed Stack]"
    stack = list(b.get_table("stack_traces").walk(stack_id))
    stack_str = ""
    for addr in stack:
        func_name = b.sym(addr, -1, show_module=False, show_offset=False)
        # if "kretprobe_trampoline" not in func_name:
        stack_str += str(func_name) + "<br>"
    return stack_str


def print_event(cpu, data, size):
    global start
    event = b[lock['name']].event(data)
    # for lock in locks:
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    # print("%-18.9f %-16s %-6d %-6d %-6d %-6f     %-15f %-6d" % (time_s, event.comm, event.pid, event.tid,
    #                                                             event.lock,
    #                                                             (float(event.present_time - start)) / 1000000000,
    #                                                             event.lock_time, event.diff))
    trace = get_stack(event.stack_id)
    if event.lock in events:
        key = event.lock
        events[key]['ts'] = event.ts
        events[key]['lock'] = event.lock
        events[key]['present_time'] = event.present_time
        events[key]['lock_time'] += event.diff
        events[key]['tid'].add(event.tid)
        events[key]['pid'].add(event.pid)
        events[key]['comm'] = event.comm
        events[key]['lock_count'] += 1
        events[key]['type'] = event.type
        if events[key]['type'] == 2:
            events[key]['type'] = 1
        if events[key]['type'] == 4:
            events[key]['type'] = 3
        if trace in events[key]['stack_traces']:
            events[key]['stack_traces'][trace]['count'] += 1
            events[key]['stack_traces'][trace]['time'] += event.diff
        else:
            events[key]['stack_traces'][trace] = {}
            events[key]['stack_traces'][trace]['count'] = 1
            events[key]['stack_traces'][trace]['time'] = event.diff
    else:
        event_dict = {'ts': event.ts,
                        'lock': event.lock,
                        'present_time': event.present_time,
                        'lock_time': event.diff,
                        'diff': event.diff,
                        'tid': {event.tid},
                        'pid': {event.pid},
                        'comm': event.comm,
                        'lock_count': 1,
                        'type': event.type,
                        'stack_traces': {trace: {'count':1, 'time':event.diff}}
                        }
        events[event_dict['lock']] = event_dict

#Process Arguments
parser = argparse.ArgumentParser(description='Monitor locking activities in the kernel')
parser.add_argument("--time", help="Time in seconds to monitor locks in kernel Default Value is 10",
                    type=int, default=10)
args = parser.parse_args()

# load BPF program
current_pid = os.getpid()
# Generate program
prog = prog_header
for lock in locks:
    prog += lock_func.replace("_ID_", str(lock['id'])).replace("_NAME_", lock['name'])

prog = prog.replace("CUR_PID", str(current_pid))

b = BPF(text=prog)
for lock in locks:
    b.attach_kprobe(event=lock['lock_func'], fn_name="lock_%s" % lock['name'])
    b.attach_kretprobe(event=lock['lock_func'], fn_name="release_%s" % lock['name'])

events = {}
# header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "LOCKTIME"))

print("Tracing locks for %d seconds" % args.time)

# process event
start = 0

# loop with callback to print_event
for lock in locks:
    b[lock['name']].open_perf_buffer(print_event, page_cnt=4096)
start_time = datetime.datetime.now()
try:
    while 1:
        b.perf_buffer_poll()
        time_elapsed = datetime.datetime.now() - start_time
        if time_elapsed.seconds > args.time:
            raise KeyboardInterrupt
except KeyboardInterrupt:
    pass
finally:
    min_lock_time = 100000000000
    for key, event in events.iteritems():
        if event['diff'] < min_lock_time:
            min_lock_time = event['diff']
    print("\nMinimum lock time is : %d\n" % min_lock_time)
    event_list = sorted(events.values(), key=lambda kv: kv['lock_time'], reverse=True)
    generate_report(event_list)
