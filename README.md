# desert

Java RMI dissector:
1. Dissecting TCP streams using ObjectInputStream.readObject(). So be careful not to be exploited through untrusted PCAP.
2. Jars of application are necessary
3. Initialization phase should be captured. By a initialization phase I mean requests to RMI registry.

## Build instructions
### Add external java libraries
```
io.pkts:pkts-core:3.0.5
io.pkts:pkts-streams:3.0.5
org.slf4j:slf4j-log4j12:1.4.0
```
## Run instructions
### Add to VM options
```
--add-opens java.base/jdk.internal.loader=ALL-UNNAMED
```