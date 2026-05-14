#ifndef SOCK_STATE_H
#define SOCK_STATE_H

struct inet_sock_state_args {
    void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8  protocol;
    __u8  saddr[4];
    __u8  daddr[4];
};

#endif