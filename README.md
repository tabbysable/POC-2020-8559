# POC-2020-8559

Exploit for CVE-2020-8559. We steal all the connections to the kubelet using iptables then rewrite the 101 or 302 responses to 307. The 101s are for modern Kubernetes versions, the 302s are for older ones.

We don't have access to the kube-apiserver's x509 cert, so kubelet webhook auth can be a problem. No problem with this kubelet config fragment, which basically re-enables the old-time kubelet-exploit:

```
authentication:
  anonymous:
    enabled: true
authorization:
  mode: AlwaysAllow
```
