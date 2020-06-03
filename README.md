# lockstat
A tool  based on eBPF to find out scalability bottlenecks in kernel.

## How to run

You have to install bcc to run the script.
```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

```
refer [How to install bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md) if needed.

Then you can run the script using
```bash
sudo python lockstat.py --time 10

```
The above command traces locks for 10 seconds and generates an HTML report in the end.
If you want to add or remove locks that are being monitored, edit the list "locks" in the script.

Refer the blog post [Building usefull tools with eBPF: Part2 Tracing the Locks in Linux Kernel](https://prathyushpv.github.io/2019/06/20/Building_usefull_tools_with_eBPF_Part2_Tracing_the_Locks_in_Linux_Kernel.html) to read more about the script. 
