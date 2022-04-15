# tls_dissect

This project is used to capture and parse TLS packets. It is useful for troubelshooting TLS sessions on remote systems where running tools like wireshark is rather hard.

Tested with TLS 1.2 and 1.3.

At this time it will output the content of ClientHello and ServerHello packets to stdout.
