# DecLimiter
A free alternative to [NetLimiter](https://www.netlimiter.com/) on Windows.

## Installation
1. Compile DecLimiter from source or get an exe from [releases](https://github.com/dec4234/DecLimiter/releases)
```shell
git clone https://github.com/dec4234/DecLimiter

cargo build --release
```

2. Download the Windivert drivers from https://www.reqrypt.org/windivert.html

3. Set your WINDIVERT_PATH environment variable to the x64/ directory of the downloaded Windivert files.

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

## Limitations
- Currently only works on Windows
- Currently only supports limiting download speed
- Selection list shows all processes, not just the ones that actually use the network card
- Each instance of DecLimiter currently can only handle 1 process

## Immediate Todo
- [ ] Implement a way to only show processes that use the network card in the selection list
- [ ] Implement a way to control multiple processes with one instance of DecLimiter
- [ ] Block upload/download completely for a process

## Long term
- [ ] Implement a GUI
- [ ] Implement a way to set different limits for different network interfaces
- [ ] Backend that works on mac and linux