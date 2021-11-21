# LAN/WAN/Network Gossip

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

_To be continued_
