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
