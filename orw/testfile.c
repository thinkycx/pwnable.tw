#include <unistd.h>  
#include <stdio.h>
#include <fcntl.h>  
void main()
{
    int  fd;
    char buf[100] = {0};
    fd = open("/tmp/flag",0,0);
    read(fd,buf,50);
    write(1,buf,50);
    close(fd);
}
