# secudp

secudp is a fork of ENet which aims to build
in encryption and server authentication on 
top of ENet's protocol. This is useful for keeping
things like chats, status updates, and the like
secret without having to look for another dependency
or spending a bit of time incorporating encryption
into the protocol. The best part is that this is
completely transparent except for some instantiation
details.

# Dependencies

* libsodium (signatures, key exchange, secret-key cryptography)

# Installation instructions

* UNIX

Run the following commands

$ autoreconf (or autoconf, if that doesn't work)
$ ./configure
$ make
$ sudo make install

* Windows

I still need to figure that out. 

# TODO

* Find out how to build the project on Windows.

