# privacidade_seguranca

Run server

Run client

Select a user from the list on file "registered_users.csv"

send message using publick key of receipient + message text

---

# Secure Messaging System with Server and Client

## Overview

This project consists of two programs: the Server and the Client. The Server maintains a list of online users, while the Client communicates with the Server and enables users to exchange messages securely.

The Server program remains online and provides information about online users to the Client. Users are added to the `registered_users.csv` file when they are online, including their public key and IP:port information. Once a user is in the registered users list, another client can send messages to them. The message exchange process occurs directly through an open socket connection.

Note that the current version lacks a graphical interface, but you can test it through the command line by passing two parameters: `<public key>` and `<message>`.

Example:

```
<public key> <message>
```

```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApBhZbGnCvVbu6la2ENsf4OgWxHz+0aI59anZwqoMh7jx+KzDmk8OHSEpxq/ojGr7ECPmUvihUqfgYI/ZinRAFiU9FpMGF/c8s1jRJ92XlS6IDsw3PCKi0Pph0Plh0aEbPw7vDtYV79PEwfZ36O072a4iyDKdkIky3zUY0xgZdxYPzYPHvyv+JMZZ8A2jS8B46NPxuxIp6BfPskmvAHTdokp0ZPyeqXurEyBtOHTz8zgcKh9t3ZrRSaELmmlZDwfyAW2O9YJjyAoMpxk51GkaXdjrleh1VqXCKvUAatKQZk7rw/j8tSQWuddSQgCfRHEuqp0YD4P0SzLRy/dE+QOnrQIDAQAB batata
```

## Server

The Server program is responsible for:

- Maintaining a list of online users.
- Receiving a user's public key, IP address, and port.
- Expecting a ping from the Client every 45 seconds; if the ping is not received, the user is removed from the online list.
- Providing the list of online users, including their public keys, IP addresses, and usernames.
TODO: Implement usernames

## Client

The Client program:

- Communicates with the Server using sockets.
- Periodically pings the Server to indicate that it is online.
- Maintains a list of online users by reading the Server's responses.
- Sends messages to online users by specifying their public key and the message.
- Supports testing through the command line, sending messages with two parameters: `<public key>` and `<message>`.

## Usage

1. Start the Server program.
2. Start the Client program.
3. To send a message to an online user, use the following command:
   ```
   <public key> <message>
   ```
4. Monitor the Server and Client interactions through the command line.

## Dependencies

- Java

## Security Considerations

- The system provides end-to-end encryption.
- Messages are authenticated using digital signatures.
- RSA encryption with PSS padding is used for message security.
- Ensure that your private keys are kept secure, as they are used for signing messages.

---

TODO: implement usernames
TODO: create UI
TODO: check if signing should also be probabilistic or deterministic is ok. Right now the users sends the message, the signed message and it's public key to prove who they are
