// Disposable local target for Frida, perf and process-memory integration tests.
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
int main(int argc, char **argv) {
    prctl(PR_SET_NAME, "snitch-fixture", 0, 0, 0);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(19999)};
    inet_pton(AF_INET,"127.0.0.1",&dst.sin_addr);
    if(argc>1) {
        inet_pton(AF_INET,argv[1],&dst.sin_addr);dst.sin_port=htons(80);
        setvbuf(stdout,NULL,_IOLBF,0);
        for(int i=0;i<600;i++) {
            int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);int ok=0;
            if(fd>=0) {
                if(connect(fd,(struct sockaddr*)&dst,sizeof(dst))==0) ok=1;
                else {struct pollfd p={.fd=fd,.events=POLLOUT};if(poll(&p,1,200)>0){int error=-1;socklen_t n=sizeof(error);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&n)==0&&error==0)ok=1;}}
                close(fd);
            }
            printf("%d\n",ok);usleep(100000);
        }
        return 0;
    }
    for(int i=0;i<600;i++) {
        int fd=socket(AF_INET,SOCK_DGRAM,0);
        if(fd>=0){connect(fd,(struct sockaddr*)&dst,sizeof(dst));send(fd,"genyra-test-payload!",19,0);close(fd);}
        usleep(100000);
    }
    return 0;
}
