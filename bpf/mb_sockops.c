/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

// 监听 socket 事件

#if ENABLE_IPV4
static inline int sockops_ipv4(struct bpf_sock_ops *skops)
{
    // 获取当前 netns 的 cookie
    __u64 cookie = bpf_get_socket_cookie_ops(skops);

    struct pair p;
    memset(&p, 0, sizeof(p));
    set_ipv4(p.sip, skops->local_ip4);
    p.sport = bpf_htons(skops->local_port);
    set_ipv4(p.dip, skops->remote_ip4);
    p.dport = skops->remote_port >> 16;
    // 在 cookie_original_dst 查找与 cookie 相关的条目
    struct origin_info *dst =
        bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    // 如果存在 cookie
    if (dst) {
        struct origin_info dd = *dst;
        // dd 保存原始目的信息
        if (!(dd.flags & 1)) {
            __u32 pid = dd.pid;
            // process ip not detected
            // 判断源 IP 和目的地址 IP 是否一致
            if (skops->local_ip4 == envoy_ip ||
                skops->local_ip4 == skops->remote_ip4) {
                // envoy to local
                // 如果一致，代表发送了错误的请求
                __u32 ip = skops->remote_ip4;
                debugf("detected process %d's ip is %pI4", pid, &ip);
                // 并将当前的 ProcessID 和 IP 信息写入 process_ip 这个 map
                bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
#ifdef USE_RECONNECT
                // bpf_htons:主机序到网络序
                // 判断远程端口是不是15006端口，如果是的话则丢弃这个连接
                if (skops->remote_port >> 16 == bpf_htons(IN_REDIRECT_PORT)) {
                    printk("incorrect connection: cookie=%d", cookie);
                    return 1;
                }
#endif
            } else {
                // envoy to envoy
                // envoy 访问 envoy
                __u32 ip = skops->local_ip4;
                // 将当前的 ProcessID 和 IP 信息写入 process_ip 这个 map
                bpf_map_update_elem(&process_ip, &pid, &ip, BPF_ANY);
                debugf("detected process %d's ip is %pI4", pid, &ip);
            }
        }
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_original_dst
        // get_sockopts 可以读取 pid 和 cookie，我们应该写一个新的 map 命名为 pair_original_dst
        // 将四元组信息和对应的原始目的地址写入 pair_original_dst 中
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_ANY);
        // 将当前 sock 和四元组保存在 sock_pair_map中
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == OUT_REDIRECT_PORT ||
               skops->local_port == IN_REDIRECT_PORT ||
               skops->remote_ip4 == envoy_ip) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}
#endif

#if ENABLE_IPV6
static inline int sockops_ipv6(struct bpf_sock_ops *skops)
{
    __u64 cookie = bpf_get_socket_cookie_ops(skops);
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.sport = bpf_htons(skops->local_port);
    p.dport = skops->remote_port >> 16;
    set_ipv6(p.sip, skops->local_ip6);
    set_ipv6(p.dip, skops->remote_ip6);

    struct origin_info *dst =
        bpf_map_lookup_elem(&cookie_original_dst, &cookie);
    if (dst) {
        struct origin_info dd = *dst;
        // get_sockopts can read pid and cookie,
        // we should write a new map named pair_original_dst
        // get_sockopts 可以读取 pid 和 cookie，我们应该写一个新的 map 命名为 pair_original_dst

        // 将四元组信息和对应的原始目的地址写入 pair_original_dst 中
        bpf_map_update_elem(&pair_original_dst, &p, &dd, BPF_ANY);
        // 将当前 sock 和四元组保存在 sock_pair_map 中
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    } else if (skops->local_port == OUT_REDIRECT_PORT ||
               skops->local_port == IN_REDIRECT_PORT ||
               ipv6_equal(skops->remote_ip6, envoy_ip6)) {
        bpf_sock_hash_update(skops, &sock_pair_map, &p, BPF_NOEXIST);
    }
    return 0;
}
#endif

__section("sockops") int mb_sockops(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
    // 被动连接
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    // 主动连接
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        switch (skops->family) {
        // 判断协议类型
#if ENABLE_IPV4
        case 2:
            // AF_INET, we don't include socket.h, because it may
            // cause an import error.
            // 处理 ipv4 协议
            return sockops_ipv4(skops);
#endif
#if ENABLE_IPV6
        case 10:
            // AF_INET6
            // 处理 ipv6 协议
            return sockops_ipv6(skops);
#endif
        }
        return 0;
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
