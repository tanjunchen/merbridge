# 主要问题

CNI 模式中的 mark 是啥意思？为啥需要标记 39807 特殊端口？其中 mark_pod_ips_map 与 local_pod_ips Map 是什么关系？
```
```

TC ingress 变更目的端口，egress 需要恢复原来的端口，那 ingress 与 egress 是什么关系？
```
ingress hook：__netif_receive_skb_core() -> sch_handle_ingress()
egress hook：__dev_queue_xmit() -> sch_handle_egress()
```

mb_connect 中的 bpf_bind 函数主要功能是？
```
/* User bpf_sock_addr struct to access socket fields and sockaddr struct passed
 * by user and intended to be used by socket (e.g. to bind to, depends on
 * attach type).
 */
struct bpf_sock_addr {
	__u32 user_family;	/* Allows 4-byte read, but no write. */
	__u32 user_ip4;		/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_port;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order
				 */
	__u32 family;		/* Allows 4-byte read, but no write */
	__u32 type;		/* Allows 4-byte read, but no write */
	__u32 protocol;		/* Allows 4-byte read, but no write */
	__u32 msg_src_ip4;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 msg_src_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__bpf_md_ptr(struct bpf_sock *, sk);
};
```

mb_connect 中的 legacy 模式是啥？为啥会有 process Map？

```
bpf_get_current_pid_tgid 尝试从 process_ip Map 中获取 pod ip。
```

tc 中的 sendmsg 与 recvmsg 是如何处理 DNS 请求的？
```
Pod 容器中的应用对外 DNS 请求(53) 将被转发到 localhost:15053(envoy 处理)。
```
