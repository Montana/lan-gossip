# _NB: This Network Gossip writeup is for myself, but making it public as it could be useful for others._


## LAN Gossip

Several distributed peer-to-peer applications require weakly-consistent knowledge of process group membership information at all participating processes. SWIM is a
generic software module that offers this service for largescale process groups. The SWIM effort is motivated by the unscalability of traditional heart-beating protocols, which either impose network loads that grow quadratically with group size, or compromise response times or false positive frequency `WRT` detecting process crashes. This sometimes can be solved with WRT Software like "Tomato".

## WAN Gossip

Unlike traditional heartbeating protocols, SWIM separates the failure detection and membership update dissemination functionalities of the membership protocol. Processes are monitored through an efficient peer-to-peer periodic randomized probing protocol. Both the expected time to first detection of each process failure, and the expected message load per member, do not vary with group size. Information about membership changes, such as process joins, drop-outs and failures, is propagated via piggybacking on ping messages and acknowledgments. A robust and fast infection style (also epidemic or `gossipstyle`)
of dissemination

The rate of false failure detections in the SWIM system is reduced by modifying the protocol to allow group members to suspect a process before declaring it as failed - this allows the system to discover and rectify false failure detections. Finally, the protocol guarantees a deterministic time bound to detect failures.

Experimental results from the SWIM prototype are presented. What is the extinsibility of the design to a WAN-Wide scale? 

## Gossip Based Dissemination Protocols

Briefly,  a  membership  protocol  provides  each  process (“member”) of the group with a locally-maintained list of other non-faulty processes in the group. The protocol en- sures that the membership list is updated with changes resulting from new members joining the group, or dropping out (either voluntarily or through a failure).  The member- ship list is made available to the application either directly in its address space,  or through a callback interface or an API. The application is free to use the contents of the list as required, e.g. gossip-based dissemination protocols would
use the list to periodically pick target members for **gossip**.

However,  actual  implementations of heartbeating suffer from scalability limitations. Sending all heartbeats to a central server leads to hot-spot creation. Sending heartbeats to all members (through either network multicast, or gossiping) leads to a message load on the network and group that grows quadratically with the group size. Heartbeating along a logical ring suffers from un- predictability of failure detection time when there are multiple failures. Unfortunately, as the group size rises, so does the likelihood of simultaneous multiple failures.

## Disallowing nodes in different datacenters to join in the same LAN gossip group

A question that was brought to me is was as follows:

>> Lets say there is `node1` in `dc1`, and `node2` in `dc2`, If you 'consul join' `node1` and `node2`, this will work and cause the LAN Gossips of `dc1` and `dc2` to become single gossip pool, not dynamic ones.

>> This would be an extremely bad accident since disjoining this gossip pool seems to require to fully shutdown all consul agents, wipe their state
and start them back up again. 

>> I can't figure out any other way to prevent this sort of accident, other than using firewall rules to firewall the LAN gossip port between datacenters.
Would be nice to have something builtin, within consul to avoid such accidental joining

This is called Gossip Cluster Mixing, a lot of people fall into this trap, and turns into quite the quagmire. 

```go
"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"
	@@ -103,7 +104,13 @@ func (c *Command) Run(args []string) int {
					address = ingr.IP
					return nil
				} else if ingr.Hostname != "" {
					// todo: for now we're resolving this hostname to an IP
					// because Consul doesn't yet support hostnames for its mesh
					// gateway addresses. We will want to remove this when it's
					// supported because in the case of EKS (the only cloud
					// that returns hostnames for its LBs) the IPs may change
					// so only the hostname is safe.
					address, unretryableErr = resolveHostname(ingr.Hostname)
					return nil
				}
			}
	@@ -149,6 +156,26 @@ func (c *Command) validateFlags(args []string) error {
	return nil
}

// resolveHostname returns the first ipv4 address for host.
func resolveHostname(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("unable to resolve hostname: %s", err)
	}
	if len(ips) < 1 {
		return "", fmt.Errorf("hostname %q had no resolveable IPs", host)
	}

	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("hostname %q had no ipv4 IPs", host)
}

// withErrLogger runs op and logs if op returns an error.
// It returns the result of op.
func withErrLogger(log hclog.Logger, op func() error) func() error {
```

The above snippet seems to put guardrails in place from this sort of thing happening, but this has happened to me a lot of times, so remember if it happens to you, don't feel bad! 

One thing to remember is The gossip algorithm tries *really* hard to maintain the connected mesh, so it can be a bit tricky to untangle when the clusters mix. The key is that the LAN gossip is on port 8301 (TCP/UDP) by default.

The easiest way to fix the coupling is to create a firewall or iptables rule to drop any traffic between the clusters. So LAN A drops any traffic to/from LAN B and
visa-versa.

Once this rule is in place, both clusters will mark the nodes in the other cluster as failed (gossip detector will mark them all as down). Then you can issue a “consul force-leave” on all the failed nodes to prevent Consul from trying to recover those nodes.

Once this is done the two clusters should be disentangled.

## Branches 

Make sure Consul checks the following:

* LAN member joining LAN pool in different DC
* LAN member joining WAN pool
* WAN member joining non-server node

You could block whichever port you run the LAN serf on (default 8300) between DC’s to prevent that type of join. It would still be possible to mix the WAN and LAN clusters locally in turn this is called "mingling gossip" or if they were in the same DC where the firewall rules didn’t apply.


_To be continued_
