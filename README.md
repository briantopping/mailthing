# Mailthing - Anti-spam toolkit and someday mail server

The author of this project started it because he was getting a lot of spam. Spam forced most folks to
cloud based mail servers over the last decade, but the Snowden revelations caused a stir and a lot of people are rethinking
their reliance on these services. A better solution to spam is in order.

Since internet email relies on the Simple Mail Transport Protocol (SMTP), someone who wants to know how this thing works 
will inevitably need to know how SMTP works.  In general, it's a very simple protocol that is a lot like HTTP in it's 
request-response structure with text-based (readable) commands over a TCP stream connection.

## Inspiration

Much of the inspiration for this project comes from the work done at http://spamcop.net. In a nutshell, forwarding spam
headers to one's account at Spamcop causes the system to parse the email headers of the spam, looking most carefully at
the server that was directly responsible for connecting to the mail server that serves the final recipient's mailbox.
It is quite common to find that this machine has been compromised by hackers and is being used to retransmit the spam
in a distributed manner, masking the original sender. Spamcop uses the WHOIS public records database to find the 
responsible party to the IP address and sends warning emails,
including the exact time and message contents. This is very effective at stopping spam as most spammers run from hacked
machines and a notice of spam from a machine is a good indication that's it's been hacked.

At the simplest level, Mailthing uses these same techniques to identify spam hosts, using them to maintain a comprehensive
blacklist of senders.  This blacklist is initially designed to be compatible with the Postfix mail suite, the dominant
internet Mail Transport Agent (MTA).  

## State of the art

### Identification of spam sources
Over time, spammers change their techniques. For instance, it is simple to assume that the owner of a network with a small
number of IP addresses that persistently send spam after notification of breach belong to a professional spammer, and 
all the addresses managed by that organization are potential spam sources. 

### Centralized blacklists
A large Akka infrastructure could easily run a DNSBL. We'll need to be careful for false positives that do things like block
major cloud providers like Gmail. 

### Cloud providers
Cloud providers are 
successful with their spam filtering in large part because they can see the same message being sent to hundreds or thousands
of users at a time, and when a number of users mark a message as spam, the message can be marked as spam in all accounts that 
received it. Further, the message identified via crowdsourcing can be used as training material to machine learning 
algorithms, further improving the accuracy of finding spam in the first place.

While this might lead one to believe that a single centralized mail server is a solution, it is exceptionally vulnerable
to eavesdropping, either via means built into the system or by simply watching all the traffic in and out of the server
cluster.

### Message provenance
DNSSEC, SMTP TLS and related technologies provide good tools to prove a sender before accepting mail from them. 
  

## System architecture vision

Mailthing v1 is contains several module types that can be composed to local requirements:

* **Mail Parser** -- Some kind of Akka Streams construction such that different parsing modules can do things in a big
scalable actor network.
* **Context Store** -- Akka Persistence against Cassandra will allow large scale operations
* **Message Interceptor** -- This will focus on Postfix for the time being.
* **MTA Router Integration** -- Once a message is identified to be rerouted, a means of modifying the message (either with
additional headers, a alternate mailbox destination, or simply deleting it) must be provided. 

### A potential initial workflow:

1. When a user receives a spam, they will manually move the spam to a "Junk" mailbox.
1. An Interceptor will periodically process the messages in that mailbox, sending them individually to the Parser stack.
1. The Parser will update the Context
1. A simple Router Integration will use the Context to provide an ACCEPT / REJECT indication to the MTA. In the case
of using Postfix, the context data is piped to [`postmap`](http://www.postfix.org/postmap.1.html), which generates the
appropriate lookup tables for blacklisting.

# Status

Tuesday, September 15, 2015:

* Right now, most of what you just read was a waste of time, sorry about that. The current state is it generates a nice 
set of rules for Postfix based on all mail in an IMAP folder.
* Previous versions required manual merging of rules as new spam arrived over time. This version keeps a quick and dirty cache
of the last run so a single operator does not have to manually merge the text files and netmasks.
* The next version should read and write directly to some format that Postfix can use directly, for instance Berkeley DB. This
is a stopgap until there's an adapter for Postfix to talk directly to the forthcoming context store.

* Probably need to use the date of the email that generated a report rather than the runtime of the tool
* We may want to delist entries after a timeout, but relisting should be with exponential addition to the last timeout period 
