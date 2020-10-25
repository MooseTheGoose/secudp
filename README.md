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

Open "secudp.vcxproj" in Visual Studio and select Build - Build Solution.
The library will then be installed in Debug\ as "secudp.lib". You can include
this file in your project along with the libsodium and secudp header files.
You must also link against ws2_32.lib and winmm.lib for any projects using
this library.

