# ssl handshake packets sniffer

## the task
You should create a go application (go version >= 1.13) that will do the following:

Run on a 64-bit Linux distribution (Centos, Ubuntu, Debian).
Sniff tcp/ip packets.
Detect among the sniffed packets detect SSL (https) handshake packets.
Print to stdout each detection in the following format: IP_SRC,TCP_SRC,IP_DST,TCP_DST,COUNT(TCP_OPTIONS).
ALTERNATIVE TASK
Do 4. using a websocket transport instead of stdout. This means you should create a minimal set of html/css/js code that will display the output whenever a user visits the dedicated URL.

OPTIONAL TASK
The app should work in Docker. Make sure you provide all the details how it would run there.

NOTES:
COUNT(TCP_OPTIONS) is a number of TCP_OPTIONS contained in the TCP/IP packet.
Please do the task as clean as possible.
Write at least some unit-tests (hint: you can use pre-saved packets as a test data).
You cannot use tcpdump for this task or any other shell command.
The task should be published to GitHub.
There should be a readme file with a description on how to compile and use the app.

## Usage 
// TODO


