# ssl handshake packets sniffer

#### The Test task 

You should create a go application (go version >= 1.13) that will do the following: 

1. Run on a 64-bit Linux distribution (Centos, Ubuntu, Debian). 
2. Sniff tcp/ip packets. 
3. Detect among the sniffed packets detect SSL (https) handshake packets. 
4. Print to stdout each detection in the following format: 
    `IP_SRC,TCP_SRC,IP_DST,TCP_DST,COUNT(TCP_OPTIONS)`. 

#### Alternative task 

Do `4.` using a websocket transport instead of stdout. This means you should create a minimal set of html/css/js code that will display the output whenever a user visits the dedicated URL. 

#### Optional task 

The app should work in Docker. Make sure you provide all the details how it would run there. 

#### Notes: 

* `COUNT(TCP_OPTIONS)` is a number of TCP_OPTIONS contained in the TCP/IP packet. 
* Please do the task as clean as possible. 
* Write at least some unit-tests (_hint_: you can use pre-saved packets as a test data). 
* You cannot use `tcpdump` for this task or any other shell command. 
* The task should be published to GitHub. 
* There should be a readme file with a description on how to compile and use the app. 

## Usage 

```
docker run --rm --name sniffer -p 443:443 wawan/sniffer
```

