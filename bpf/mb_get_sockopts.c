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
#include <linux/bpf.h>
#include <linux/in.h>

#define MAX_OPS_BUFF_LENGTH 4096
// 80 是 ORIGINAL_DST 在内核中的编号
#define SO_ORIGINAL_DST 80

// 劫持 cgroup/getsockopt 事件

__section("cgroup/getsockopt") int mb_get_sockopt(struct bpf_sockopt *ctx)
{
    // currently, eBPF can not deal with optlen more than 4096 bytes, so, we
    // should limit this.
    // ebpf 无法处理大于 4096 字节的数据
    if (ctx->optlen > MAX_OPS_BUFF_LENGTH) {
        debugf("optname: %d, force set optlen to %d, original optlen %d is too "
               "high",
               ctx->optname, MAX_OPS_BUFF_LENGTH, ctx->optlen);
        ctx->optlen = MAX_OPS_BUFF_LENGTH;
    }
    // envoy will call getsockopt with SO_ORIGINAL_DST, we should rewrite it to
    // return original dst info.
    // envoy 将使用 SO_ORIGINAL_DST 调用 getsockopt，我们应该重写它以返回原始 dst 信息。
    if (ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }
    struct pair p;
    memset(&p, 0, sizeof(p));
    p.dport = bpf_htons(ctx->sk->src_port);
    p.sport = ctx->sk->dst_port;
    struct origin_info *origin;
    switch (ctx->sk->family) {
    // 判断协议类型
#if ENABLE_IPV4
    case 2: // ipv4
        set_ipv4(p.dip, ctx->sk->src_ip4);
        set_ipv4(p.sip, ctx->sk->dst_ip4);
        // 根据四元组信息从 pair_original_dst 取出原始目的地址并返回
        origin = bpf_map_lookup_elem(&pair_original_dst, &p);
        if (origin) {
            // rewrite original_dst
            // 重写原始目的地址
            ctx->optlen = (__s32)sizeof(struct sockaddr_in);
            // 边界检查
            if ((void *)((struct sockaddr_in *)ctx->optval + 1) >
                ctx->optval_end) {
                printk("optname: %d: invalid getsockopt optval", ctx->optname);
                return 1;
            }
            // 将系统调用返回值重置为零
            ctx->retval = 0;
            struct sockaddr_in sa = {
                .sin_family = ctx->sk->family,
                .sin_addr.s_addr = get_ipv4(origin->ip),
                .sin_port = origin->port,
            };
            *(struct sockaddr_in *)ctx->optval = sa;
        }
        break;
#endif
#if ENABLE_IPV6
    case 10: // ipv6
        set_ipv6(p.dip, ctx->sk->src_ip6);
        set_ipv6(p.sip, ctx->sk->dst_ip6);
        origin = bpf_map_lookup_elem(&pair_original_dst, &p);
        // 根据四元组信息从 pair_original_dst 取出原始目的地址并返回
        if (origin) {
            // rewrite original_dst
            // 重写原始目的地址
            ctx->optlen = (__s32)sizeof(struct sockaddr_in6);
            if ((void *)((struct sockaddr_in6 *)ctx->optval + 1) >
                ctx->optval_end) {
                printk("optname: %d: invalid getsockopt optval", ctx->optname);
                return 1;
            }
            ctx->retval = 0;
            if ((void *)((struct sockaddr_in6 *)ctx->optval + 1) >
                ctx->optval_end) {
                printk("optname: %d: invalid getsockopt optval", ctx->optname);
                return 1;
            }
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ctx->optval;
            sa->sin6_family = ctx->sk->family;
            sa->sin6_port = origin->port;
            set_ipv6(sa->sin6_addr.in6_u.u6_addr32, origin->ip);
        }
        break;
#endif
    }
    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
