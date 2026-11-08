# DecLimiter
A free alternative to [NetLimiter](https://www.netlimiter.com/) on Windows.

![](assets/img.png)

## Installation
1. Compile DecLimiter from source or get an exe from [releases](https://github.com/dec4234/DecLimiter/releases)
```shell
git clone https://github.com/dec4234/DecLimiter

cargo build --release
```

2. Install [Windows Packet Filter](https://github.com/wiresock/ndisapi/releases)

## Usage
There are 2 provided ways to limit the speed of a process.

### Selection List
1. Run the .exe file as an adminstrator
2. Select a process from the list
3. Set a download speed

### CLI
```shell
-p, --pid = The process id of the process you want to control
-d, --download = Set the maximum download speed of the process (Optional)
-u, --upload = Set the maximum upload speed of the process (Optional)
-g, --garbage-collect = Set the garbage collection delay in seconds [Default: 60]
```

Speeds are in bits per second, with an optional unit: `K`, `M`, `G`, `T` or `P`
(steps of 1000), and an optional `bps` suffix. For example, `-d 10Mbps` limits
the download to 10 megabits per second (1.25 MB/s). The minimum is `8` (1 byte
per second).

## Limitations
- Currently only works on Windows
- Currently only supports limiting download speed
- Selection list shows all processes, not just the ones that actually use the network card
- Each instance of DecLimiter currently can only handle 1 process

## Todo
- Doesn't reconnect if adapter disconnects and reconnects
- Readings still ~5% inaccurate

## Long term
- [ ] Implement a way to set different limits for different network interfaces
- [ ] Backend that works on mac and linux