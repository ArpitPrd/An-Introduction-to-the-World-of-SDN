## Goal

- learning software defined newtorks
- basic network policies using openflow style APIs
- Mininet + Ryu Controller for implementations and experimentations

## Part 1: Hub Controller and Learning Switch 

- There are two types of controller::
    - Hub Controller 
        - Redirects all traffic from switch to a controller
        - maintains a MAC addr table of all hosts connected to their ports
        - if known: instructs to switch to the corresponding port
        - else: flood
        - no flow rules on switch
    - Learnign Switch Controller
        - Flow rules here
        - learns as the packets come along
        - once flow rule in place, can direct packets without controller interferences, send directly to the correct port
        - only packets that do not match any of the flow rules, end up sending to the controller

- Steps:
    - Implement:
        - Controller Hub
        - Leanign Switch
    - Run controller against the given topology and answer
        - Run pingall for both of the controller
            - Record the installed rules in both the switches
            - explain observation
        - Throughput tests
            - h1 and h3 uising iperf in both cases
            - record speed
            - explain diff between the two controllers types with respect to the record speed

## Part 2: Layer 2 shortest path routing

- build cutom Ryu controller that performs shortest path routing across the network, while still performing the L2 forwarding operations
- Assume entire network in the file is part of a single subnet hence same mask
- Controller Must:
    - Read the net, link cost matrix and represent them as weighted graph 
    - D Alg to find the shortest distance path from source and dest (use the python built-in lib to be able to do that), but know how the algorithm works
    - implement load balancing strategy for multiple equal cost paths ECMP. Randomly select among equal paths
    - provide flag for ECMP
    - Install open flow rules for each flow (no idea)
- Testing and Measurement:
    - run iperf between H1 and H2 for 10s, in 2 parallel tcp connection (can be specified while running iperf command)
    - run the exp twice once with ECMP flag and once w/o
    - record 
        - thpt and 
        - flow rules in both runs
    - summarize and explain the results
- Bonus:
    - implement a weighted load balancing strategy, selects path for flow based on current utilisation 
    - send to rel. lightly loaded
    - Validation
        - run iperf with udp flows that generate different loads on the network
        - validate the flows are installed on paths in weighted manner
        - report:
            - explain load balancing system and validation results comparing them with random selection methodology 


## Setup and Resources

- Same installation of mininet as in A2
- Ryu:
    - need to install ryu for this assignment
    - installation instr and tut: https://ryu.readthedocs.io/en/latest/getting_started.html
- commands for mininet
    - ping between host h1 and host h2: h1 ping h2
    - any command to host h1: h1 cmd
    - to open a new terminal for host h1: xterm h1. set up x11 forwarding
    - print rules installed on switches dpctl dump-flows
    - running a ryu app: ryu-manager app.py

## Submission Intruction 
- pdf: report.pdf
- Part1: 
    - SS for:
        - rules as well as 
        - the ping/iperf results in the report pdf
    - two controller applucation scripts: p1_learning.py and p1_hub.py
- Part2:
    - Controller application: p2_l2spf.py
    - assumpotion, results in the report
    - bonus file: p2bonus_l2spf.py
- Part3:
- Part4:



## Baadal Notes:


- Always to --observe-links flag

(ryuenv) baadalvm@baadalvm:~/COL333_A3/AkshatCode/part3$ ryu-manager p3_l3spf.py 
Traceback (most recent call last):
  File "/home/baadalvm/COL333_A3/ryuenv/bin/ryu-manager", line 5, in <module>
    from ryu.cmd.manager import main
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/ryu/cmd/manager.py", line 22, in <module>
    from ryu.lib import hub
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/ryu/lib/hub.py", line 30, in <module>
    import eventlet
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/__init__.py", line 17, in <module>
    from eventlet import convenience
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/convenience.py", line 7, in <module>
    from eventlet.green import socket
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/green/socket.py", line 4, in <module>
    __import__('eventlet.green._socket_nodns')
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/green/_socket_nodns.py", line 11, in <module>
    from eventlet import greenio
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/greenio/__init__.py", line 3, in <module>
    from eventlet.greenio.base import *  # noqa
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/greenio/base.py", line 32, in <module>
    socket_timeout = eventlet.timeout.wrap_is_timeout(socket.timeout)
  File "/home/baadalvm/COL333_A3/ryuenv/lib/python3.10/site-packages/eventlet/timeout.py", line 166, in wrap_is_timeout
    base.is_timeout = property(lambda _: True)
TypeError: cannot set 'is_timeout' attribute of immutable type 'TimeoutError'

same error, I tjhink the last time you asked to me downgrade my python version, can you do trhat 

use python3.9