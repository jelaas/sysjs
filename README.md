sysjs
=====

javascript vm with system extensions.

Uses duktape for javascript vm.

Examples
========
cli.js
=========
Sys=Sys1;
Sys.dprint(1, "Number of arguments: "+Sys.argc + "\n");
for(i=0;i<Sys.argc;i++)
    Sys.dprint(1, i + ": "+ Sys[i] + "\n");

daemon.js
=========
var Sys=Sys1;

pid = Sys.fork();
if(pid > 0) {
    Sys._exit(0);
}

Sys.setsid();
Sys.chdir("/");
fd = Sys.open("/dev/null",Sys.O_RDWR, 0);
Sys.dup2(fd, 0);
Sys.dup2(fd, 1);
Sys.dup2(fd, 2);
if(fd > 2) Sys.close(fd);

while(1) {
    Sys.sleep(10);
}

file.js
=========
Sys=Sys1;

fd = Sys.open('/etc/passwd', Sys.O_RDONLY, 0);
len = Sys.lseek(fd, 0, Sys.SEEK_END);
Sys.lseek(fd, 0, Sys.SEEK_SET);
Sys.dprint(1, "Len: "+len+"\n");
res = Sys.read(fd, len);
Sys.write(1, res.buffer, res.rc);
Sys.close(fd);

stat=Sys.lstat('/etc/group');
Sys.dprint(1, JSON.stringify(stat)+"\n");

pipes.js
=========
Sys=Sys1;

fds = Sys.pipe();
Sys.dprint(1, fds.rc + "\n");
Sys.dprint(1, fds[0] + "\n");
Sys.dprint(1, fds[1] + "\n"); 

poll.js
=========
Sys=Sys1;

while(1) {
    ret = Sys.poll( [ { fd: 0, events: Sys.POLLIN } ], 1, 5000);
    Sys.dprint(1, JSON.stringify(ret)+"\n");
    if(ret) {
	for(i=0;i<ret.fds.length;i++) {
	    if(ret.fds[i].revents) {
		res = Sys.read(ret.fds[i].fd, 1024);
		if(res.rc > 0)
		    Sys.dprint(1, "Read "+res.buffer);
	    }
	}
    }
}

tcpclient.js
=========
Sys=Sys1;
fd = Sys.socket(Sys.AF_INET, Sys.SOCK_STREAM, Sys.IPPROTO_TCP);
Sys.connect(fd, { in: '127.0.0.1', port: 80 });
Sys.dprint(fd, "Hello");
Sys.close(fd);


tcpserver.js
=========
Sys=Sys1;

fd = Sys.socket(Sys.AF_INET, Sys.SOCK_STREAM, Sys.IPPROTO_TCP);
Sys.setsockopt(fd, Sys.SOL_SOCKET, Sys.SO_REUSEADDR, 1);
Sys.bind(fd, { in: '127.0.0.1', port: 7780 });
Sys.listen(fd, 10);

while(1) {
    res = Sys.accept(fd);
    if(res.rc >= 0) {
	Sys.dprint(res.rc, res.famliy + " " + res.addr);
	Sys.close(res.rc);
    }
}

wait.js
=========
Sys=Sys1;

pid = Sys.fork();

if(pid == 0) {
    Sys._exit(10);
}

r = Sys.waitpid(pid, 0);
Sys.dprint(1, JSON.stringify(r) + "\n");

