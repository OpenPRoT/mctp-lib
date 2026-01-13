# MCTP Control Protocol endpoint example
Example that listens for a Set Endpoint ID MCTP Control message, sets the ID and responds to the request.

Uses the standalone std implementation for the Stack and attaches to a specified serial port.
(Use a tool like _socat_ to attach to the linux MCTP stack through PTYs)

Errors after the specified timeout.

The timeout and serial port are set by constants in the example.

# Testing the example with `mctpd`

### Setup [mctpd](https://github.com/CodeConstruct/mctp/) as a service conntected to d-bus
To check that `mctpd` is running and available on the d-bus `busctl` can be used.
```bash
sudo busctl tree au.com.codeconstruct.MCTP1
```
(If `mctpd` fails to connect to the d-bus, the config might be missing.
Copy the `conf/mctpd-dbus.conf` to the apropiate directory (usually `/etc/dbus-1/system.d/`).)


### Create _pty_ ports with socat
```bash
socat -d -d -x pty,rawer,icanon=0,nonblock,link=pts1 pty,rawer,icanon=0,nonblock,link=pts2
```
This will create two linked _pty_ devices (`pts1`, `pts2`) in the current working directory.

### Setup the linux mctp-stack
Make sure the `mctp-serial` module is loaded:
```bash
sudo modprobe mctp-serial
```

Link the _pty_:
```bash
sudo mctp link serial pts2
```
(this has to continue running in the background)

Bring the link up:
```bash
sudo mctp link set mctpserial0 up
```

Add a local endpoint ID for the bus-owner:
```bash
sudo mctp addr add 9 dev mctpserial0
```

## Run the example
```bash
cargo run --example mctp-control-endpoint
```
and then trigger `mctpd` to assign an EID to the endpoint.
```bash
sudo busctl call au.com.codeconstruct.MCTP1 /au/com/codeconstruct/mctp1/interfaces/mctpserial0 au.com.codeconstruct.MCTP.BusOwner1 AssignEndpoint ay 0
```
(the interface path might be different (use `busctl tree` and `busctl introspect` to list the available interfaces and methods))

Both the example and mctpd should now report success.

