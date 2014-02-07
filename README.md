bro_regex
=========

Python script to autogenerate and test regular expressions to parse bro log files

usage:
./bro_rex_tester.py [bro_log_dir]

A couple of caveats - i adjusted the regex to account for ipv4 and ipv6 as well as dashes and (empty)s. Feel free to change the regex to martch your ussage model. 

See one example of the output i used to create the QRadar parsing XML for the files, weird and notice logs.
