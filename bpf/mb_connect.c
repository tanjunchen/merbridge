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

#include "headers/cgroup.h"
#include "headers/helpers.h"
#include "headers/maps.h"
#include "headers/mesh.h"
#include <linux/bpf.h>
#include <linux/in.h>

// 劫持 connect 系统调用

// 处理 IPv4
#if ENABLE_IPV4
static __u32 outip = 1;

// 处理 udp 流量
static inline int udp_connect4(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
    if (!is_port_listen_in_cgroup(ctx, 0, localhost, DNS_CAPTURE_PORT,
                                  DNS_CAPTURE_PORT_FLAG)) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        // 忽略查询不是来自网格注入的 pod，或者未启用 DNS CAPTURE 的连接请求。
        return 1;
    }

    // 0xffffffff 表示最大的无符号整数值
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, ctx->user_ip4);
        origin.port = ctx->user_port;
        // save original dst
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        ctx->user_ip4 = localhost;
    }
    return 1;
}

// 处理 tcp 流量
static inline int tcp_connect4(struct bpf_sock_addr *ctx)
{
    struct cgroup_info cg_info;
    if (!get_current_cgroup_info(ctx, &cg_info)) {
        return 1;
    }
    // 我们只处理由 istio 或 kuma 管理的 pod 的流量。
    if (!cg_info.is_in_mesh) {
        // bypass normal traffic. we only deal pod's
        // traffic managed by istio or kuma.
        return 1;
    }
    __u32 curr_pod_ip;
    __u32 _curr_pod_ip[4];
    set_ipv6(_curr_pod_ip, cg_info.cgroup_ip);
    curr_pod_ip = get_ipv4(_curr_pod_ip);

    if (curr_pod_ip == 0) {
        debugf("get current pod ip error");
    }
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    __u32 dst_ip = ctx->user_ip4;
    // istio-proxy 用户身份 uid 不是 1337
    if (uid != SIDECAR_USER_ID) {
        // inbound 方向
        // 检查是否为本地回环地址（loopback address），如果应用调用的是本地回环地址，则跳过
        if ((dst_ip & 0xff) == 0x7f) {
            // app call local, bypass.
            return 1;
        }
        // 获取当前 netns 的 cookie
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        
        // app 调用其他的应用，uid 不是 1337 且应用没有调用本地
        debugf("call from user container: cookie: %d, ip: %pI4, port: %d",
               cookie, &dst_ip, bpf_htons(ctx->user_port));

        // we need redirect it to envoy. 需要重定向到 envoy 处理
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;
        origin.flags = 1;
        // 将 cookie 和源地址信息更新到 cookie_original_dst 中，更新成功返回 0，失败返回负值
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        if (curr_pod_ip) {
            struct pod_config *pod =
                bpf_map_lookup_elem(&local_pod_ips, _curr_pod_ip);
            if (pod) {
                // 判断是否在 Mesh 排除 IS_EXCLUDE_PORT 范围
                int exclude = 0;
                IS_EXCLUDE_PORT(pod->exclude_out_ports, ctx->user_port,
                                &exclude);
                if (exclude) {
                    debugf("ignored dest port by exclude_out_ports, ip: "
                           "%pI4, port: %d",
                           &curr_pod_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                // 判断是否在 Mesh 排除 IS_EXCLUDE_IPRANGES 范围
                IS_EXCLUDE_IPRANGES(pod->exclude_out_ranges, dst_ip, &exclude);
                debugf("exclude ipranges: %x, exclude: %d",
                       pod->exclude_out_ranges[0].net, exclude);
                if (exclude) {
                    debugf(
                        "ignored dest ranges by exclude_out_ranges, ip: %pI4",
                        &dst_ip);
                    return 1;
                }
                int include = 0;
                // 判断是否在 Mesh 纳管 IS_INCLUDE_PORT 范围
                IS_INCLUDE_PORT(pod->include_out_ports, ctx->user_port,
                                &include);
                if (!include) {
                    debugf("dest port %d not in pod(%pI4)'s include_out_ports, "
                           "ignored.",
                           bpf_htons(ctx->user_port), &curr_pod_ip);
                    return 1;
                }
                // 判断是否在 Mesh 纳管 IS_INCLUDE_IPRANGES 范围
                IS_INCLUDE_IPRANGES(pod->include_out_ranges, dst_ip, &include);
                if (!include) {
                    debugf("dest %pI4 not in pod(%pI4)'s include_out_ranges, "
                           "ignored.",
                           &dst_ip, &curr_pod_ip);
                    return 1;
                }
            } else {
                debugf("current pod ip found(%pI4), but can not find pod_info "
                       "from local_pod_ips",
                       &curr_pod_ip);
            }
            // todo port or ipranges ignore.
            // if we can get the pod ip, we use bind func to bind the pod's ip
            // as the source ip to avoid quaternions conflict of different pods.

            // 如果我们能获取到 pod 的 ip，我们使用 bind func 将 pod的 ip 绑定为源 ip，以避免不同 pod 的四元数冲突。
            struct sockaddr_in addr = {
                .sin_addr =
                    {
                        .s_addr = curr_pod_ip,
                    },
                .sin_port = 0,
                .sin_family = 2,
            };
            // todo(kebe7jun) use the following way will cause an error like:
            /*
                578: (07) r2 += -40
                ; if (bpf_bind(ctx, &addr, sizeof(struct sockaddr_in))) {
                579: (bf) r1 = r6
                580: (b7) r3 = 16
                581: (85) call bpf_bind#64
                invalid indirect read from stack R2 off -40+8 size 16
                processed 1136 insns (limit 1000000) max_states_per_insn 1
               total_states 81 peak_states 81 mark_read 20

                libbpf: -- END LOG --
                libbpf: failed to load program 'cgroup/connect4'
                libbpf: failed to load object 'mb_connect.o'
            */
            // addr.sin_addr.s_addr = curr_pod_ip;
            // addr.sin_port = 0;
            // addr.sin_family = 2;
            if (bpf_bind(ctx, &addr, sizeof(struct sockaddr_in))) {
                debugf("bind %pI4 error", &curr_pod_ip);
            }
            ctx->user_ip4 = localhost;
        } else {
            // if we can not get the pod ip, we rewrite the dest address.
            // The reason we try the IP of the 127.128.0.0/20 segment instead of
            // using 127.0.0.1 directly is to avoid conflicts between the
            // quaternions of different Pods when the quaternions are
            // subsequently processed.
            // 如果获取不到 pod ip，我们重写 dest address。之所以尝试 127.128.0.0/20 网段的IP，而不是直接使用 127.0.0.1，
            // 是为了避免不同 Pod 的四元数在四元数匹配时发生冲突，随后处理。
            // 因为在不同的Pod中，可能产生冲突的四元组，使用此方式即可巧妙地避开冲突
            ctx->user_ip4 = bpf_htonl(0x7f800000 | (outip++));
            if (outip >> 20) {
                outip = 1;
            }
        }
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        // outbound 方向 从 envoy 进程中访问其他应用
        __u32 _dst_ip[4];
        set_ipv4(_dst_ip, dst_ip);
        // 目的 pod ip 没有在节点中，绕过
        struct pod_config *pod = bpf_map_lookup_elem(&local_pod_ips, _dst_ip);
        if (!pod) {
            // dst ip is not in this node, bypass
            debugf("dest ip: %pI4 not in this node, bypass", &dst_ip);
            return 1;
        }

        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        // 目的地址在当前节点，但是不在当前 pod 中，处理同节点加速
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv4(origin.ip, dst_ip);
        origin.port = ctx->user_port;  
        if (curr_pod_ip) {
             // 如果存在则属于 envoy 到其他 envoy
            if (curr_pod_ip != dst_ip) {
                // call other pod, need redirect port.
                // 处理 Mesh IS_EXCLUDE_PORT、IS_INCLUDE_PORT
                int exclude = 0;
                IS_EXCLUDE_PORT(pod->exclude_in_ports, ctx->user_port,
                                &exclude);
                if (exclude) {
                    debugf("ignored dest port by exclude_in_ports, ip: %pI4, "
                           "port: %d",
                           &dst_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                int include = 0;
                IS_INCLUDE_PORT(pod->include_in_ports, ctx->user_port,
                                &include);
                if (!include) {
                    debugf("ignored dest port by include_in_ports, ip: %pI4, "
                           "port: %d",
                           &dst_ip, bpf_htons(ctx->user_port));
                    return 1;
                }
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
            }
            origin.flags |= 1;
        } else {
            // 不能获取到 Pod ip，则回退到 legacy 模式
            // can not get current pod ip, we use the legacy mode.

            // u64 bpf_get_current_pid_tgid(void)
            // Return A 64-bit integer containing the current tgid and
            //                 pid, and created as such: current_task->tgid <<
            //                 32
            //                | current_task->pid.
            // pid may be thread id, we should use tgid
            __u32 pid = bpf_get_current_pid_tgid() >> 32; // tgid
            void *curr_ip = bpf_map_lookup_elem(&process_ip, &pid);
            if (curr_ip) {
                // envoy 到其他的 envoy
                if (*(__u32 *)curr_ip != dst_ip) {
                    debugf("enovy to other, rewrite dst port from %d to %d",
                           ctx->user_port, IN_REDIRECT_PORT);
                    ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
                }
                origin.flags |= 1;
                // envoy to app, no rewrite
                // envoy 到应用程序，不用重写
            } else {
                origin.flags = 0;
                origin.pid = pid;
#ifdef USE_RECONNECT
                // envoy to envoy
                // try redirect to 15006
                // but it may cause error if it is envoy call self pod,
                // in this case, we can read src and dst ip in sockops,
                // if src is equals dst, it means envoy call self pod,
                // we should reject this traffic in sockops,
                // envoy will create a new connection to self pod.
                
                // envoy 访问 Envoy，重定向到 15006 端口
                // 尝试重定向到 15006 但如果是 envoy 访问自身 pod 可能会导致错误，
                // 在这种情况下，我们可以在 sockops 中读取 src 和 dst ip，如果 src 等于 dst，
                // 则意味着 envoy 调用 self pod，我们应该在 sockops 中拒绝此流量，envoy 将创建一个到 self pod 的新连接。
                ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
#endif
            }
        }
        // 获取当前 netns 的 cookie
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        debugf("call from sidecar container: cookie: %d, ip: %pI4, port: %d",
               cookie, &dst_ip, bpf_htons(ctx->user_port));
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }

    return 1;
}

// 处理 ipv4
__section("cgroup/connect4") int mb_sock_connect4(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect4(ctx);
    case IPPROTO_UDP:
        return udp_connect4(ctx);
    default:
        return 1;
    }
}
#endif

// 处理 ipv6
#if ENABLE_IPV6
static inline int udp_connect6(struct bpf_sock_addr *ctx)
{
#if MESH != ISTIO && MESH != KUMA
    // only works on istio and kuma
    return 1;
#endif
    // 忽略非 udp 连接
    if (bpf_htons(ctx->user_port) != 53) {
        return 1;
    }
     // 判断端口是否在监听当前的 netns，以 istio 为例，OUT_REDIRECT_PORT是 15001
     // 如果 15001 端口没有监听当前 ns，则绕过，只需要处理 istio 管理的 pod 间流量
    if (!(is_port_listen_current_ns6(ctx, ip_zero6, OUT_REDIRECT_PORT) &&
          is_port_listen_udp_current_ns6(ctx, localhost6, DNS_CAPTURE_PORT))) {
        // this query is not from mesh injected pod, or DNS CAPTURE not enabled.
        // we do nothing.
        return 1;
    }

    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        // needs rewrite
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv6(origin.ip, ctx->user_ip6);
        origin.port = ctx->user_port;
        // save original dst
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("update origin cookie failed: %d", cookie);
        }
        ctx->user_port = bpf_htons(DNS_CAPTURE_PORT);
        set_ipv6(ctx->user_ip6, localhost6);
    }
    return 1;
}

static inline int tcp_connect6(struct bpf_sock_addr *ctx)
{
    struct cgroup_info cg_info;
    if (!get_current_cgroup_info(ctx, &cg_info)) {
        return 1;
    }
    // 处理 istio 流量
    if (!cg_info.is_in_mesh) {
        // bypass normal traffic. we only deal pod's
        // traffic managed by istio or kuma.
        return 1;
    }

    __u32 curr_pod_ip[4];
    set_ipv6(curr_pod_ip, cg_info.cgroup_ip);
    __u32 dst_ip[4];
    set_ipv6(dst_ip, ctx->user_ip6);
    __u64 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != SIDECAR_USER_ID) {
        if (ipv6_equal(dst_ip, localhost6)) {
            // app call local, bypass.
            // 应用访问本地，透传流量
            return 1;
        }
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        // app call others
        // 应用访问其他应用
        debugf("call from user container: cookie: %d, ip: %pI6c, port: %d",
               cookie, dst_ip, bpf_htons(ctx->user_port));

        // we need redirect it to envoy.
        // 重定向流量到 envoy
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        set_ipv6(origin.ip, dst_ip);
        origin.port = ctx->user_port;

        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_ANY)) {
            printk("write cookie_original_dst failed");
            return 0;
        }
        // TODO(dddddai): add support for annotations

        // if we can get the pod ip, we use bind func to bind the pod's ip
        // as the source ip to avoid quaternions conflict of different pods.
        // 如果我们能获取到 pod ip，我们使用 bind func 将 pod 的 ip 绑定为源 ip，避免不同 pod 的四元组冲突。
        struct sockaddr_in6 addr;
        set_ipv6(addr.sin6_addr.in6_u.u6_addr32, curr_pod_ip);
        addr.sin6_port = 0;
        addr.sin6_family = 10;
        if (bpf_bind(ctx, (struct sockaddr_in6 *)&addr,
                     sizeof(struct sockaddr_in6))) {
            printk("bind %pI6c error", curr_pod_ip);
        }
        set_ipv6(ctx->user_ip6, localhost6);
        ctx->user_port = bpf_htons(OUT_REDIRECT_PORT);
    } else {
        // from envoy to others
        // envoy 访问其他应用的流量
        if (!bpf_map_lookup_elem(&local_pod_ips, dst_ip)) {
            // dst ip is not in this node, bypass
            debugf("dest ip: %pI6c not in this node, bypass", dst_ip);
            return 1;
        }
        // dst ip is in this node, but not the current pod,
        // it is envoy to envoy connecting.
        // dst ip 在此节点中，但不在当前 pod 中，它是 envoy 到 envoy 连接。
        struct origin_info origin;
        memset(&origin, 0, sizeof(origin));
        origin.port = ctx->user_port;
        set_ipv6(origin.ip, dst_ip);
        if (!ipv6_equal(dst_ip, curr_pod_ip)) {
            debugf("enovy to other, rewrite dst port from %d to %d",
                   ctx->user_port, bpf_htons(IN_REDIRECT_PORT));
            ctx->user_port = bpf_htons(IN_REDIRECT_PORT);
        }
        __u64 cookie = bpf_get_socket_cookie_addr(ctx);
        debugf("call from sidecar container: cookie: %d, ip: %pI6c, port: %d",
               cookie, dst_ip, bpf_htons(ctx->user_port));
        if (bpf_map_update_elem(&cookie_original_dst, &cookie, &origin,
                                BPF_NOEXIST)) {
            printk("update cookie origin failed");
            return 0;
        }
    }
    return 1;
}

// 处理 ipv6
__section("cgroup/connect6") int mb_sock_connect6(struct bpf_sock_addr *ctx)
{
    switch (ctx->protocol) {
    case IPPROTO_TCP:
        return tcp_connect6(ctx);
    case IPPROTO_UDP:
        return udp_connect6(ctx);
    default:
        return 1;
    }
}
#endif

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
