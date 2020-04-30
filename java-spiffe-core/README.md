# JAVA-SPIFFE Core

Core functionality to fetch X509 and JWT SVIDs from the Workload API.

## Create a X509Source

```
TBD
```

## Netty Event Loop thread number configuration

Use the variable `io.netty.eventLoopThreads` to configure the number of threads for the Netty Event Loop Group. 

By default, it is `availableProcessors * 2`.
