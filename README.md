# pynfcap
Python NetFlowV9 collector


Pure python Netflow v9 parser.  Parses flows using dynamically created ctypes structures.  These ctypes structures are are made from incoming NetFlow v9 templates and NetFlow "type" definitions found in nfTables.py.

Works with multiple senders.  Recommend increasing UDP buffer size, NetFlow traffic can be voluminous.

This needs work.  I'm going to move the NetFlow type definitions into a YAML file so others can easily add them.  I'm also going to add an option to output binary instead of CSV, and conversely add support to read from binary files in addition to reading from sockets.

This way, if you want to scale better, you can launch two instances... one that reads from sockets and dumps the binary to disk, and another process that reads from binary files and dumps to CSV.

You'd use the same program to do this:  "nfcap.py"

Performance is OK, as far as I can tell.  There is zero copy up until you write to CSV.  I am removing the use of any dict() in the program, to increase performance.

