# Trace is a simple 'traceroute'-like utility written in C++

## Installation: 
- git clone git@github.com:VasyaKaban/trace.git
- cd trace
- mkdir build/{Type of build}(Debug/Release/etc...)
- cd build/{Type of build}
- cmake -DCMAKE_BUILD_TYPE={Type of build} ../../
- cmake --build
- ctest (for tests execution)

## Requirements: 
- C++20
- Boost.Test

## Execution:  
  trace [--hops=$value(>0)] [--samples=$value(>0)] --host=$host_name [--timeout=$value(>0)] [--out_file=path]
  Flags:  
	**` --help `** show usage infromation  
  **` --host `** sets the host name which route we want to explore  
	**` --hops `** sets the maximum TTL hops for socket. This value must be greater than zero  
	**` --samples `** sets the maximum samples per hop. Each sample is a send/receive iteration with remote host information collection and timer measurements! This value must be greater than zero  
	**` --timeout `** sets timeout in milliseconds for reading. This value must be a positive integer.  
	**` --out_file `** sets the path for an output file. By default output will be flushed into the stdout  

 ## WARNING!
 This utility uses ICMP-echo/Time exceeded packets hence you need to execute it with root privileges (via sudo, doas, su or setuid/setgid)
 
