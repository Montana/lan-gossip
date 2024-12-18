![image](https://user-images.githubusercontent.com/20936398/142780193-37883a4a-f269-4474-bcb7-7398987bff9e.png)


# _NB: This Network Gossip writeup is for myself, but making it public as it could be useful for others._

## What is the Gossip Protocol? 

I'm going to give you a very top down definition, with a gossip protocol, nodes individually gossip their state, and the states of other nodes, to one another to eventually achieve a unified view of the system. If you want a more in-depth definition please visit: https://en.wikipedia.org/wiki/Gossip_protocol

## LAN Gossip

Several distributed peer-to-peer applications require weakly-consistent knowledge of process group membership information at all participating processes. SWIM is a
generic software module that offers this service for largescale process groups. The SWIM effort is motivated by the unscalability of traditional heart-beating protocols, which either impose network loads that grow quadratically with group size, or compromise response times or false positive frequency `WRT` detecting process crashes. This sometimes can be solved with WRT Software like "Tomato".

<img width="1404" alt="Screen Shot 2021-11-21 at 1 33 48 PM" src="https://user-images.githubusercontent.com/20936398/142779769-1a6ddbcc-3ba1-40a5-9c6a-f6bc3cf0d35a.png">


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

## Piggybacking Gossip 

**Piggybacking Gossip** information on application-generated messages could in theory be a fail-safe solution when running a high performance network.  The protocols are simulated and evaluated with a fault-injection model for scalable distributed systems comprised of clusters of workstations connected by high-performance networks, such as the CPlant machine at Sandia National Laboratories. The model supports permanent and transient node and link failures, with rates
specified at simulation time, for processors functioning in a fail-silent fashion. Through high-fidelity, CAD-base modeling and simulation, we demonstrate the strengths and weaknesses of each approach in terms of agreement time, number of gossips, and overall scalability.

<img width="729" alt="Screen Shot 2021-11-21 at 1 31 15 PM" src="https://user-images.githubusercontent.com/20936398/142779650-c086bd2c-e43a-4302-904f-6da38066613c.png">


## Branches 

Make sure Consul checks the following:

* LAN member joining LAN pool in different DC
* LAN member joining WAN pool
* WAN member joining non-server node

You could block whichever port you run the LAN serf on (default 8300) between DC’s to prevent that type of join. It would still be possible to mix the WAN and LAN clusters locally in turn this is called "mingling gossip" or if they were in the same DC where the firewall rules didn’t apply.

## Anti-Entropy Gossip, Gossip Skeletons, Rumor Mongering & Spacial Gossip

**Anti-Entropy** Gossipping is very expensive, this is because it looks at the entire database, but fixes any distro erros. You can even get better results when you combine anti-entropy gossipping with **rumor mongering**. This happens via: 

* Propagation of one given update, this can be limited (max 'K' times or with some probability, as countlessp papers have showed us) 
* selectPeer: A random peer from the network can send a Gossip request 
* Gossip Skeleton 
* Rumor Mongering As an Instance 

Now let's get into **Gossip Skeletons**:

* The push-pull method 
* The active thread inits communication in this case **push** and receives peerSate in this case **pull**. 

Now let's switch lanes into **Rumor mongering**:

* Gossipping nodes pick another node in each cycle, this is what I call "The Gossip Cycle", they do not need to know all the nodes, hence the term **rumor**. 
* The pattern of communication between nodes defines a random graph 
* When anti-entropy gossip finds an undelivered update: we redistribute 
* There are various additional tricks to deal with removals using things like **Spacial Gossip**. 

On to some more space, let's get into Spacial Gossip:

* Spacial gossip is peer selection that is biased according to distance of the peer, so for example lets say we have a node, and this node is called a, so `node a`, node a is proportional to `node d` where `d` is the distance of `node a`.
* If the underlying topology is linear, then the expected traffic per link per cycle can be expected as follows:

```bash
< 0;
< 1;
< 1 < a < 2;
a = 2;
a > 2
```
## Spacial Gossip (continued)

When a=2 provides the optimal balance between speed and network traffic, we find several key advantages:

* Information spreads through the network in O(log n) rounds, where n represents node count
* Network overhead remains manageable while ensuring reliable propagation
* Convergence time stays predictable even as the network grows

The effectiveness heavily depends on topology considerations:

* For datacenter environments, rack awareness becomes crucial
* With geo-distributed systems, latency measurements inform distance metrics
* Hierarchical networks may need modified distance calculations

## Implementation Examples

### Basic Gossip Node Implementation

Here's a simple example of a gossip node implementation in Go:

```go
type GossipNode struct {
    ID        string
    peers     map[string]*Peer
    state     map[string]interface{}
    mutex     sync.RWMutex
    maxPeers  int
}

func NewGossipNode(id string, maxPeers int) *GossipNode {
    return &GossipNode{
        ID:       id,
        peers:    make(map[string]*Peer),
        state:    make(map[string]interface{}),
        maxPeers: maxPeers,
    }
}

func (n *GossipNode) StartGossip(interval time.Duration) {
    ticker := time.NewTicker(interval)
    go func() {
        for range ticker.C {
            peer := n.selectRandomPeer()
            if peer != nil {
                n.sendGossip(peer)
            }
        }
    }()
}

func (n *GossipNode) selectRandomPeer() *Peer {
    n.mutex.RLock()
    defer n.mutex.RUnlock()
    
    if len(n.peers) == 0 {
        return nil
    }
    
    peerIds := make([]string, 0, len(n.peers))
    for id := range n.peers {
        peerIds = append(peerIds, id)
    }
    
    randomIndex := rand.Intn(len(peerIds))
    return n.peers[peerIds[randomIndex]]
}
```

### Spatial Gossip Implementation

Here's how you might implement spatial gossip with distance-based peer selection:

```go
type SpatialNode struct {
    *GossipNode
    location Point
}

type Point struct {
    X, Y float64
}

func (n *SpatialNode) selectPeerByDistance() *Peer {
    n.mutex.RLock()
    defer n.mutex.RUnlock()
    
    type peerDistance struct {
        peer     *Peer
        distance float64
    }
    
    distances := make([]peerDistance, 0, len(n.peers))
    
    // Calculate distances to all peers
    for _, peer := range n.peers {
        dist := calculateDistance(n.location, peer.location)
        distances = append(distances, peerDistance{peer, dist})
    }
    
    // Sort by distance
    sort.Slice(distances, func(i, j int) bool {
        return distances[i].distance < distances[j].distance
    })
    
    // Select peer with probability proportional to 1/d^2
    totalWeight := 0.0
    weights := make([]float64, len(distances))
    for i, pd := range distances {
        weights[i] = 1 / math.Pow(pd.distance, 2)
        totalWeight += weights[i]
    }
    
    // Random selection based on weights
    r := rand.Float64() * totalWeight
    current := 0.0
    for i, weight := range weights {
        current += weight
        if r <= current {
            return distances[i].peer
        }
    }
    
    return nil
}
```

### Anti-Entropy Implementation

Here's an example of implementing anti-entropy synchronization:

```go
type StateEntry struct {
    Value     interface{}
    Version   int64
    Timestamp time.Time
}

func (n *GossipNode) AntiEntropy(peer *Peer) error {
    // Get local state digest
    localDigest := n.getStateDigest()
    
    // Exchange digests
    remoteDigest, err := peer.GetDigest()
    if err != nil {
        return fmt.Errorf("failed to get remote digest: %v", err)
    }
    
    // Find differences
    toSend := make(map[string]*StateEntry)
    toRequest := make([]string, 0)
    
    for key, localEntry := range localDigest {
        if remoteEntry, exists := remoteDigest[key]; !exists {
            // Remote missing this key
            toSend[key] = n.state[key]
        } else if localEntry.Version > remoteEntry.Version {
            // Local version newer
            toSend[key] = n.state[key]
        } else if localEntry.Version < remoteEntry.Version {
            // Remote version newer
            toRequest = append(toRequest, key)
        }
    }
    
    // Send updates to peer
    if len(toSend) > 0 {
        err = peer.UpdateState(toSend)
        if err != nil {
            return fmt.Errorf("failed to send updates: %v", err)
        }
    }
    
    // Request updates from peer
    if len(toRequest) > 0 {
        updates, err := peer.GetState(toRequest)
        if err != nil {
            return fmt.Errorf("failed to get updates: %v", err)
        }
        n.mergeUpdates(updates)
    }
    
    return nil
}
```

### Failure Detection Example

Here's an implementation of SWIM-style failure detection:

```go
type FailureDetector struct {
    node           *GossipNode
    suspicionTime  time.Duration
    probeInterval  time.Duration
    suspectNodes   map[string]time.Time
    failedNodes    map[string]struct{}
    mutex          sync.RWMutex
}

func (fd *FailureDetector) Start() {
    ticker := time.NewTicker(fd.probeInterval)
    go func() {
        for range ticker.C {
            fd.probeRandomNode()
        }
    }()
    
    // Check for suspect timeouts
    go func() {
        for range time.Tick(fd.probeInterval) {
            fd.checkSuspects()
        }
    }()
}

func (fd *FailureDetector) probeRandomNode() {
    target := fd.node.selectRandomPeer()
    if target == nil {
        return
    }
    
    // Send probe
    err := target.Probe()
    if err != nil {
        fd.mutex.Lock()
        fd.suspectNodes[target.ID] = time.Now()
        fd.mutex.Unlock()
        
        // Disseminate suspicion
        fd.node.Broadcast(SuspicionMessage{
            NodeID: target.ID,
            Time:   time.Now(),
        })
    }
}

func (fd *FailureDetector) checkSuspects() {
    fd.mutex.Lock()
    defer fd.mutex.Unlock()
    
    now := time.Now()
    for nodeID, suspectTime := range fd.suspectNodes {
        if now.Sub(suspectTime) > fd.suspicionTime {
            // Move from suspect to failed
            delete(fd.suspectNodes, nodeID)
            fd.failedNodes[nodeID] = struct{}{}
            
            // Notify about failure
            fd.node.Broadcast(FailureMessage{
                NodeID: nodeID,
                Time:   now,
            })
        }
    }
}
```

## Implementation Considerations 

### Network Partition Handling

Network partitions require careful handling in gossip protocols:

* Implement robust partition detection mechanisms
* Use versioning for conflict resolution during healing
* Define clear state merge strategies 
* Consider vector clocks for causality tracking

### Security Considerations

Security cannot be an afterthought:

* Implement strong node authentication
* Use encrypted gossip messages
* Consider message signing for integrity
* Deploy rate limiting against DoS

### Performance Optimization

Several techniques can improve performance:

* Batch updates to reduce network overhead
* Implement message compression
* Use delta updates when possible
* Deploy priority queues for critical updates
* Add backpressure mechanisms

## Best Practices 

### Configuration Management

* Start with conservative timeouts
* Implement gradual timeout adjustment
* Document all parameters thoroughly
* Provide sensible defaults

### Deployment Strategy

* Begin with small clusters
* Use canary deployments
* Maintain backward compatibility
* Plan incremental upgrades

## Future Directions

The gossip protocol space continues evolving:

### Machine Learning Integration

* Adaptive peer selection
* Anomaly detection
* Parameter optimization
* Predictive maintenance

### Edge Computing Applications

* IoT network adaptation
* Mobile edge computing support
* Handling intermittent connectivity
* Resource constraint management

## Conclusion

Gossip protocols remain fundamental to distributed systems, providing scalability through decentralization. Key takeaways:

* Network topology and distance metrics need careful consideration
* Security and partition handling are critical concerns
* Monitoring is essential for production systems
* Regular configuration review ensures optimal operation
* Edge computing brings new challenges and opportunities

Understanding these protocols deeply helps build robust, scalable distributed systems. As we continue advancing, gossip protocols will keep evolving to meet new challenges in distributed computing.

