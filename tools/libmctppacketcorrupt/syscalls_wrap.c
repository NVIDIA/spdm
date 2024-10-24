/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include "mctp.h"
#include "pktcorrupt.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Functions pointers defs*/
typedef int (*real_close_t)(int __fd);
typedef int (*real_connect_t)(int __fd, const struct sockaddr* __addr,
                              socklen_t __len);
typedef ssize_t (*real_recv_t)(int sockfd, void* buf, size_t len, int flags);

typedef int (*real_epoll_wait_t)(int epfd, struct epoll_event* events,
                                 int maxevents, int timeout);
typedef ssize_t (*real_send_t)(int socket, const void* buffer, size_t length,
                               int flags);

typedef int (*real_epoll_ctl_t)(int epfd, int op, int fd,
                                struct epoll_event* event);

/* Global read function wrappers */
static real_close_t real_close = NULL;
static real_connect_t real_connect = NULL;
static real_recv_t real_recv = NULL;
static real_epoll_wait_t real_epoll_wait = NULL;
static real_send_t real_send = NULL;
static real_epoll_ctl_t real_epoll_ctl = NULL;

static const char* mctp_pcie_sock = "\0mctp-pcie-mux";
static const char* mctp_spi_sock = "\0mctp-spi-mux";

static int mctp_pcie_fd = INVALID_VALUE;
static int mctp_spi_fd = INVALID_VALUE;
static epoll_data_t mctp_pcie_epoll_data;
static epoll_data_t mctp_spi_epoll_data;

/* IOSYS connect wrapper */
int _iosys_connect(int __fd, const struct sockaddr* __addr, socklen_t __len)
{
    bool need_init = false;
    if (!real_connect)
    {
        real_connect = (real_connect_t)(uintptr_t)dlsym(RTLD_NEXT, "connect");
        need_init = true;
    }
    if (!real_connect)
    {
        perror("## Connect: Unable to load symbol ##");
        return -1;
    }
    if (!__addr)
    {
        fprintf(stderr, "## Connect: Empty sockaddr ##\n");
        errno = EINVAL;
        return -1;
    }
    if (need_init)
    {
        int err = corrupt_init();
        if (err < 0)
        {
            fprintf(stderr,
                    "##Connect: Packet corrupt lib init error: (%i) ##\n", err);
            return err;
        }
    }
    const struct sockaddr_un* aun = (const struct sockaddr_un*)__addr;
    const size_t sock_len = __len - sizeof(aun->sun_family);
    const char* name_buf = aun->sun_path;
    if (!memcmp(name_buf, mctp_pcie_sock, sock_len))
    {
        fprintf(stderr, "## Connect: PCIe sock detected fd: %i ##\n", __fd);
        mctp_pcie_fd = __fd;
    }
    if (!memcmp(name_buf, mctp_spi_sock, sock_len))
    {
        fprintf(stderr, "## Connect: SPI sock detected fd: %i ##\n", __fd);
        mctp_spi_fd = __fd;
    }
    int real_ret = real_connect(__fd, __addr, __len);
    return real_ret;
}
__asm__(".symver _iosys_connect,connect@GLIBC_2.4");

/* IOSYS read wrapper */
ssize_t _iosys_recv(int sockfd, void* buf, size_t len, int flags)
{
    int real_ret;
    if (!real_recv)
    {
        real_recv = (real_recv_t)(uintptr_t)dlsym(RTLD_NEXT, "recv");
    }
    if (!real_recv)
    {
        perror("## Recv: Unable to load symbol for real recv ##");
        return -1;
    }
    real_ret = corrupt_fake_recv_packet(sockfd, buf, len);
    if (real_ret > 0)
    {
        return real_ret;
    }
    bool mctp_match = false;
    if (sockfd == mctp_pcie_fd)
    {
        mctp_match = true;
    }
    if (sockfd == mctp_spi_fd)
    {
        mctp_match = true;
    }
    real_ret = real_recv(sockfd, buf, len, flags);
    if (real_ret > 0 && mctp_match)
    {
        real_ret = corrupt_recv_packet(buf, len, real_ret);
    }
    return real_ret;
}
__asm__(".symver _iosys_recv,recv@GLIBC_2.4");

/* IOSYS send wrapper */
ssize_t _iosys_send(int sockfd, const void* buffer, size_t length, int flags)
{
    if (!real_send)
    {
        real_send = (real_send_t)(uintptr_t)dlsym(RTLD_NEXT, "send");
    }
    if (!real_send)
    {
        perror("## Send: Unable to load symbol for real send ##");
        return -1;
    }
    bool mctp_match = false;
    if (sockfd == mctp_pcie_fd)
    {
        mctp_match = true;
    }
    if (sockfd == mctp_spi_fd)
    {
        mctp_match = true;
    }
    if (mctp_match)
    {
        int ret = corrupt_send_packet(sockfd, buffer, length);
        if (ret == 0)
        {
            return real_send(sockfd, buffer, length, flags);
        }
        return ret;
    }
    return real_send(sockfd, buffer, length, flags);
}
__asm__(".symver _iosys_send,send@GLIBC_2.4");

/* IOSYS close wrapper */
int _iosys_close(int __fd)
{
    if (!real_close)
    {
        real_close = (real_close_t)(uintptr_t)dlsym(RTLD_NEXT, "close");
    }
    if (!real_close)
    {
        perror("## Close: Unable to load symbol ##");
        return -1;
    }
    if (__fd == mctp_pcie_fd)
    {
        mctp_pcie_fd = INVALID_VALUE;
    }
    if (__fd == mctp_spi_fd)
    {
        mctp_spi_fd = INVALID_VALUE;
    }
    if (mctp_pcie_fd == INVALID_VALUE && mctp_spi_fd == INVALID_VALUE)
    {
        corrupt_deinit();
    }
    return real_close(__fd);
}
__asm__(".symver _iosys_close,close@GLIBC_2.4");

// return true if rd is dropped otherwise false
static bool process_epoll_fd_data(int fd)
{
    int available_bytes;
    if (ioctl(fd, FIONREAD, &available_bytes) == -1)
    {
        return false;
    }
    if (available_bytes >= 5)
    {
        char mctp_hdr[5];
        int bytes_peeked = recv(fd, mctp_hdr, sizeof(mctp_hdr), MSG_PEEK);
        if (bytes_peeked == sizeof(mctp_hdr))
        {
            if (corrupt_pkt_should_be_dropped(mctp_hdr[mctp_offs_eid],
                                              mctp_hdr[mctp_offs_code]))
            {
                char drop_buffer[1024];
                while (available_bytes > 0)
                {
                    int bytes_read =
                        recv(fd, drop_buffer, sizeof(drop_buffer), 0);
                    if (bytes_read < 0)
                    {
                        break;
                    }
                    available_bytes -= bytes_read;
                }
                return true;
            }
        }
    }
    return false;
}

int _iosys_epoll_wait(int epfd, struct epoll_event* events, int maxevents,
                      int timeout)
{
    int nev;
    if (!real_epoll_wait)
    {
        real_epoll_wait =
            (real_epoll_wait_t)(uintptr_t)dlsym(RTLD_NEXT, "epoll_wait");
    }
    const int fake_fd = corrupt_fake_fd_has_data();
    if (fake_fd > 0)
    {
        epoll_data_t* edp = NULL;
        if (fake_fd == mctp_pcie_fd)
        {
            edp = &mctp_pcie_epoll_data;
        }
        else if (fake_fd == mctp_spi_fd)
        {
            edp = &mctp_spi_epoll_data;
        }
        if (edp)
        {
            events[0].events = EPOLLIN;
            events[0].data = *edp;
            return 1;
        }
    }
    for (;;)
    {
        nev = real_epoll_wait(epfd, events, maxevents, timeout);
        /**
         * Currently because in the sdbusplus epoll uses callback handles
         * instead of fd, we are unable to recognize correct fd so we just use
         * peek function to check if data are for our fd or not
         */
        if (nev <= 0)
        {
            return nev;
        }
        if (process_epoll_fd_data(mctp_pcie_fd))
            continue;
        if (process_epoll_fd_data(mctp_spi_fd))
            continue;
        break;
    }
    return nev;
}
__asm__(".symver _iosys_epoll_wait,epoll_wait@GLIBC_2.4");

int _iosys_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    if (!real_epoll_ctl)
    {
        real_epoll_ctl =
            (real_epoll_ctl_t)(uintptr_t)dlsym(RTLD_NEXT, "epoll_ctl");
    }
    int ret = real_epoll_ctl(epfd, op, fd, event);
    if (!ret)
    {
        if (fd == mctp_pcie_fd)
        {
            if (op == EPOLL_CTL_ADD)
            {
                mctp_pcie_epoll_data = event->data;
            }
            else if (op == EPOLL_CTL_DEL)
            {
                mctp_pcie_epoll_data.fd = INVALID_VALUE;
            }
        }
        if (fd == mctp_spi_fd)
        {
            if (op == EPOLL_CTL_ADD)
            {
                mctp_spi_epoll_data = event->data;
            }
            else if (op == EPOLL_CTL_DEL)
            {
                mctp_spi_epoll_data.fd = INVALID_VALUE;
            }
        }
    }
    return ret;
}
__asm__(".symver _iosys_epoll_ctl,epoll_ctl@GLIBC_2.4");