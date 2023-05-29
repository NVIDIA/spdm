#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include "pktcorrupt.h"


/* Global read function wrappers */
static int (*real_close)(int __fd) = NULL;
static int (*real_connect)(int __fd, const struct sockaddr * __addr, socklen_t __len) = NULL;
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;

static const char* mctp_pcie_sock =  "\0mctp-pcie-mux";
static const char* mctp_spi_sock =  "\0mctp-spi-mux";

#define EMPTY_FD -1
static int mctp_pcie_fd = EMPTY_FD;
static int mctp_spi_fd = EMPTY_FD;

/* IOSYS connect wrapper */
int _iosys_connect(int __fd, const struct sockaddr * __addr, socklen_t __len)
{
    bool need_init = false;
    if(!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
        need_init = true;
    }
    if(!real_connect) {
        perror("## Connect: Unable to load symbol ##");
        return -1;
    }
    if(!__addr) {
        fprintf(stderr,"## Connect: Empty sockaddr ##\n");
        errno = EINVAL;
        return -1;
    }
    if(need_init) {
        int err = corrupt_init();
        if(err<0) {
            fprintf(stderr, "##Connect: Packet corrupt lib init error: (%i) ##\n", err);
            return err;
        }
    }
    const struct sockaddr_un* aun = (const struct sockaddr_un*)__addr;
    const size_t sock_len = __len - sizeof(aun->sun_family);
    const char*  name_buf = aun->sun_path;
    if(!memcmp(name_buf, mctp_pcie_sock, sock_len)) {
        fprintf(stderr,"## Connect: PCIe sock detected fd: %i ##\n", __fd);
        mctp_pcie_fd = __fd;
    }
    if(!memcmp(name_buf, mctp_spi_sock, sock_len)) {
        fprintf(stderr,"## Connect: SPI sock detected fd: %i ##\n", __fd);
        mctp_spi_fd = __fd;
    }
    int real_ret = real_connect(__fd, __addr, __len);
    return real_ret;
}
__asm__(".symver _iosys_connect,connect@GLIBC_2.4");



/* IOSYS read wrapper */
ssize_t _iosys_recv(int sockfd, void *buf, size_t len, int flags)
{
    if(!real_recv) {
        real_recv = dlsym(RTLD_NEXT, "recv");
    }
    if(!real_recv) {
        perror("## Recv: Unable to load symbol for real recv ##");
        return -1;
    }
    bool mctp_match = false;
    if(sockfd==mctp_pcie_fd) {
        mctp_match = true;
    }
    if(sockfd==mctp_spi_fd) {
        mctp_match = true;
    }
    int real_ret =  real_recv(sockfd, buf, len, flags);
    if(real_ret>0 && mctp_match) {
        real_ret = corrupt_recv_packet(buf, len, real_ret);
    }
    return real_ret;
}
__asm__(".symver _iosys_recv,recv@GLIBC_2.4");




/* IOSYS close wrapper */
int _iosys_close(int __fd)
{
    if(!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
    }
    if(!real_close) {
        perror("## Close: Unable to load symbol ##");
        return -1;
    }
    if(__fd==mctp_pcie_fd) {
        mctp_pcie_fd = EMPTY_FD;
    }
    if(__fd==mctp_spi_fd) {
        mctp_spi_fd = EMPTY_FD;
    }
    if(mctp_pcie_fd == EMPTY_FD && mctp_spi_fd == EMPTY_FD) {
        corrupt_deinit();
    }
    return real_close(__fd);
}
__asm__(".symver _iosys_close,close@GLIBC_2.4");

