# Session Traversal Utilities for NAT (STUN) Data model

This document distills the message formats listed in all RFC documents related to the STUN protocol.

## [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)

### [Section 11.1](https://datatracker.ietf.org/doc/html/rfc3489#section-11.1) Message header

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      STUN Message Type        |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Transaction ID                        |
|                           (128 bits)                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Message Types can take on the following values:

```text
0x0001: Binding Request
0x0101: Binding Response
0x0111: Binding Error Response
0x0002: Shared Secret Request
0x0102: Shared Secret Response
0x0112: Shared Secret Error Response
```

The message length is the count, in bytes, of the size of the
message, not including the 20 byte header.

The transaction ID is a 128 bit identifier. It also serves as salt
to randomize the request and the response. All responses carry the
same identifier as the request they correspond to.

### [Section 11.2](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2) Message attributes

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Value                            ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The following types are defined:

```text
0x0001: MAPPED-ADDRESS
0x0002: RESPONSE-ADDRESS
0x0003: CHANGE-REQUEST
0x0004: SOURCE-ADDRESS
0x0005: CHANGED-ADDRESS
0x0006: USERNAME
0x0007: PASSWORD
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: REFLECTED-FROM
```

Attributes with values greater than `0x7FFF` are optional, which
means that the message can be processed by the client or server even
though the attribute is not understood. Attributes with values less
than or equal to `0x7FFF` are mandatory to understand, which means that
the client or server cannot process the message unless it understands
the attribute.

### [Section 11.2.1](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.1) Attribute MAPPED-ADDRESS

The MAPPED-ADDRESS attribute indicates the mapped IP address and
port. It consists of an eight bit address family, and a sixteen bit
port, followed by a fixed length value representing the IP address.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|x x x x x x x x|    Family     |           Port                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Address                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The port is a network byte ordered representation of the mapped port.
The address family is always 0x01, corresponding to IPv4. The first
8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
aligning parameters on natural boundaries. The IPv4 address is 32
bits.

### [Section 11.2.2](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.2) Attribute RESPONSE-ADDRESS

The RESPONSE-ADDRESS attribute indicates where the response to a
Binding Request should be sent. Its syntax is identical to MAPPED-
ADDRESS.

### [Section 11.2.3](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.3) Attribute CHANGED-ADDRESS

The CHANGED-ADDRESS attribute indicates the IP address and port where
responses would have been sent from if the "change IP" and "change
port" flags had been set in the CHANGE-REQUEST attribute of the
Binding Request. The attribute is always present in a Binding
Response, independent of the value of the flags. Its syntax is
identical to MAPPED-ADDRESS.

### [Section 11.2.4](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.4) Attribute CHANGE-REQUEST

The attribute is 32 bits long, although only two bits (A and B) are used:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The meaning of the flags is:

A: This is the "change IP" flag. If true, it requests the server
to send the Binding Response with a different IP address than the
one the Binding Request was received on.

B: This is the "change port" flag. If true, it requests the
server to send the Binding Response with a different port than the
one the Binding Request was received on.

### [Section 11.2.5](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.5) Attribute SOURCE-ADDRESS

The SOURCE-ADDRESS attribute is present in Binding Responses. It
indicates the source IP address and port that the server is sending
the response from. Its syntax is identical to that of MAPPED-
ADDRESS.

### [Section 11.2.6](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.6) Attribute USERNAME

The value of USERNAME is a variable length opaque value. Its length
MUST be a multiple of 4 (measured in bytes) in order to guarantee
alignment of attributes on word boundaries.

### [Section 11.2.7](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.7) Attribute PASSWORD

The value of PASSWORD is a variable length value that is to be used
as a shared secret. Its length MUST be a multiple of 4 (measured in
bytes) in order to guarantee alignment of attributes on word
boundaries.

### [Section 11.2.8](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.8) Attribute MESSAGE-INTEGRITY

The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [13] of the
STUN message. Since it uses the SHA1 hash, the HMAC will be 20 bytes.

### [Section 11.2.9](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.9) Attribute ERROR-CODE

The ERROR-CODE attribute is present in the Binding Error Response and Shared Secret Error Response.
It is a numeric value in the range of 100 to 699 plus a textual reason phrase encoded in UTF-8,
and is consistent in its code assignments and semantics with [SIP](https://datatracker.ietf.org/doc/html/rfc3489#ref-10) and [HTTP](https://datatracker.ietf.org/doc/html/rfc3489#ref-15).
The reason phrase is meant for user consumption, and can be anything appropriate for the response code.
The lengths of the reason phrases MUST be a multiple of 4 (measured in bytes). This can
be accomplished by added spaces to the end of the text, if necessary.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  0                      |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Reason Phrase (variable)                 ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The class represents the hundreds digit of the response code. The
value MUST be between 1 and 6. The number represents the response
code modulo 100, and its value MUST be between 0 and 99.

The following response codes, along with their recommended reason
phrases (in brackets) are defined at this time:

 - `400 (Bad Request)` The request was malformed. The client should not
retry the request without modification from the previous
attempt.


 - `401 (Unauthorized)` The Binding Request did not contain a MESSAGE-
INTEGRITY attribute.


 - `420 (Unknown Attribute)` The server did not understand a mandatory
attribute in the request.


 - `430 (Stale Credentials)` The Binding Request did contain a MESSAGE-
INTEGRITY attribute, but it used a shared secret that has
expired. The client should obtain a new shared secret and try
again.


 - `431 (Integrity Check Failure)` The Binding Request contained a
MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
This could be a sign of a potential attack, or client
implementation error.


 - `432 (Missing Username)` The Binding Request contained a MESSAGE-
INTEGRITY attribute, but not a USERNAME attribute. Both must be
present for integrity checks.


 - `433 (Use TLS)` The Shared Secret request has to be sent over TLS, but
was not received over TLS.


 - `500 (Server Error)` The server has suffered a temporary error. The
client should try again.


 - `600 (Global Failure)` The server is refusing to fulfill the request.
The client should not retry.

### [Section 11.2.10](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.10) Attribute UNKNOWN-ATTRIBUTES

The UNKNOWN-ATTRIBUTES attribute is present only in a Binding Error
Response or Shared Secret Error Response when the response code in
the ERROR-CODE attribute is 420.

The attribute contains a list of 16 bit values, each of which
represents an attribute type that was not understood by the server.
If the number of unknown attributes is an odd number, one of the
attributes MUST be repeated in the list, so that the total length of
the list is a multiple of 4 bytes.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 1 Type           |     Attribute 2 Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 3 Type           |     Attribute 4 Type    ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### [Section 11.2.11](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.11) Attribute REFLECTED-FROM

The attribute contains the identity (in terms of IP address) of the source where the request came from.
Its purpose is to provide traceability, so that a STUN server cannot be used as a reflector for denial-of-service attacks.

Its syntax is identical to the MAPPED-ADDRESS attribute.


## [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)

### [Section 6](https://datatracker.ietf.org/doc/html/rfc5389#section-6) Message header

STUN messages are encoded in binary using network-oriented format
(most significant byte or octet first, also commonly known as big-
endian). 

All STUN messages MUST start with a 20-byte header followed by zero
or more Attributes. The STUN header contains a STUN message type,
magic cookie, transaction ID, and message length.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Message Type field is decomposed further into the following
structure:

```text
 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|M|M|M|M|M|C|M|M|M|C|M|M|M|M|
|B|A|9|8|7|1|6|5|4|0|3|2|1|0|
+--+--+-+-+-+-+-+-+-+-+-+-+-+
```

Here the bits in the message type field are shown as most significant (MB) through least significant (M0).
MB through M0 represent a 12-bit encoding of the method.
C1 and C0 represent a 2-bit encoding of the class. 
A class of `0b00` is a request, a class of `0b01` is an indication, a class of `0b10` is a success response, and a class of `0b11` is an error response.
This specification defines a single method, Binding.
The method and class are orthogonal, so that for each method, a request, success response, error response, and indication are possible for that method.
Extensions defining new methods MUST indicate which classes are permitted for that method.

For example, a Binding request has class=`0b00` (request) and method=`0b000000000001` (Binding) and is encoded into the first 16 bits as `0x0001`. 
A Binding response has class=`0b10` (success response) and method=`0b000000000001`, and is encoded into the first 16 bits as `0x0101`.

The Magic Cookie field MUST contain the fixed value `0x2112A442` in network byte order.

The Transaction ID is a 96-bit identifier, used to uniquely identify STUN transactions.

The Message Length MUST contain the size, in bytes, of the message not including the 20-byte STUN header.
Since all STUN attributes are padded to a multiple of 4 bytes, the last 2 bits of this field are always zero.

### [Section 15](https://datatracker.ietf.org/doc/html/rfc5389#section-15) Message attributes

After the STUN header are zero or more attributes.
Each attribute MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
Each STUN attribute MUST end on a 32-bit boundary.
As mentioned above, all fields in an attribute are transmitted most significant bit first.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Type                  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Value (variable)                     ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The value in the length field MUST contain the length of the Value part of the attribute, prior to padding, measured in bytes. 
Since STUN aligns attributes on 32-bit boundaries, attributes whose content is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of padding so that its value contains a multiple of 4 bytes. 
The padding bits are ignored, and may be any value.

Attributes with type values between `0x0000` and `0x7FFF` are comprehension-required attributes, which means that the STUN agent cannot successfully process the message unless it understands the attribute.
Attributes with type values between `0x8000` and `0xFFFF` are comprehension-optional attributes.

### [Section 15.1](https://datatracker.ietf.org/doc/html/rfc5389#section-15.1) Attribute MAPPED-ADDRESS

The MAPPED-ADDRESS attribute indicates a reflexive transport address
of the client. It consists of an 8-bit address family and a 16-bit
port, followed by a fixed-length value representing the IP address.
If the address family is IPv4, the address MUST be 32 bits. If the
address family is IPv6, the address MUST be 128 bits. All fields
must be in network byte order.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X X X X X X X X|    Family     |           Port                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Addr(32 bits for v4 or 128 bits for v6)           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The address family can take on the following values:

```text
0x01 : IPv4
0x02 : IPv6
```

The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be ignored by receivers.

### [Section 15.2](https://datatracker.ietf.org/doc/html/rfc5389#section-15.2) Attribute XOR-MAPPED-ADDRESS

The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS attribute, except that the reflexive transport address is obfuscated through the XOR function.

The format of the XOR-MAPPED-ADDRESS is:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|X X X X X X X X|    Family     |           Port                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|             Addr(32 bits for v4 or 128 bits for v6)           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Family represents the IP address family, and is encoded
identically to the Family in MAPPED-ADDRESS.

Port is computed by taking the mapped port in host byte order, XOR'ing it with the most significant 16 bits of the magic cookie, and then the converting the result to network byte order. 
If the IP address family is IPv4, Address is computed by taking the mapped IP address in host byte order, XOR'ing it with the magic cookie, and converting the result to network byte order.
If the IP address family is IPv6, Address is computed by taking the mapped IP address in host byte order, XOR'ing it with the concatenation of the magic cookie and the 96-bit transaction ID, and converting the result to network byte order.

### [Section 15.3](https://datatracker.ietf.org/doc/html/rfc5389#section-15.3) Attribute USERNAME

The value of USERNAME is a variable-length value.
It MUST contain a [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629) encoded sequence of less than 513 bytes, and MUST have been processed using [SASLprep](https://datatracker.ietf.org/doc/html/rfc4013).

### [Section 15.4](https://datatracker.ietf.org/doc/html/rfc5389#section-15.4) Attribute MESSAGE-INTEGRITY

The MESSAGE-INTEGRITY attribute contains an [HMAC-SHA1](https://datatracker.ietf.org/doc/html/rfc2104) of the STUN message.
Since it uses the SHA1 hash, the HMAC will be 20 bytes.

### [Section 15.5](https://datatracker.ietf.org/doc/html/rfc5389#section-15.5) Attribute FINGERPRINT

The FINGERPRINT attribute MAY be present in all STUN messages. 
The value of the attribute is computed as the CRC-32 of the STUN message up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with the 32-bit value 0x5354554e.

### [Section 15.6](https://datatracker.ietf.org/doc/html/rfc5389#section-15.6) Attribute ERROR-CODE

The ERROR-CODE attribute is used in error response messages. It
contains a numeric error code value in the range of 300 to 699 plus a
textual reason phrase encoded in [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629), and is consistent
in its code assignments and semantics with [SIP](https://datatracker.ietf.org/doc/html/rfc3261) [RFC3261] and [HTTP](https://datatracker.ietf.org/doc/html/rfc2616). The reason phrase is meant for user consumption, and can
be anything appropriate for the error code. Recommended reason
phrases for the defined error codes are included in the IANA registry
for error codes. The reason phrase MUST be a UTF-8 encoded
sequence of less than 128 characters (which can be as long as 763
bytes).

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved, should be 0         |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Reason Phrase (variable)                  ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Reserved bits SHOULD be 0, and are for alignment on 32-bit
boundaries. Receivers MUST ignore these bits. The Class represents
the hundreds digit of the error code. The value MUST be between 3
and 6. The Number represents the error code modulo 100, and its
value MUST be between 0 and 99.

The following error codes, along with their recommended reason
phrases, are defined:

 - `300 Try Alternate` The client should contact an alternate server for
this request. This error response MUST only be sent if the
request included a USERNAME attribute and a valid MESSAGE-
INTEGRITY attribute; otherwise, it MUST NOT be sent and error
code 400 (Bad Request) is suggested. This error response MUST
be protected with the MESSAGE-INTEGRITY attribute, and receivers
MUST validate the MESSAGE-INTEGRITY of this response before
redirecting themselves to an alternate server.


 - `400 Bad Request` The request was malformed. The client SHOULD NOT
retry the request without modification from the previous
attempt. The server may not be able to generate a valid
MESSAGE-INTEGRITY for this error, so the client MUST NOT expect
a valid MESSAGE-INTEGRITY attribute on this response.


 - `401 Unauthorized` The request did not contain the correct
credentials to proceed. The client should retry the request
with proper credentials.


 - `420 Unknown Attribute` The server received a STUN packet containing
a comprehension-required attribute that it did not understand.
The server MUST put this unknown attribute in the UNKNOWN-
ATTRIBUTE attribute of its error response.


 - `438 Stale Nonce` The NONCE used by the client was no longer valid.
The client should retry, using the NONCE provided in the
response.


 - `500 Server Error` The server has suffered a temporary error. The
client should try again.


### [Section 15.7](https://datatracker.ietf.org/doc/html/rfc5389#section-15.7) Attribute REALM

It MUST be a [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629) encoded sequence of less than 128 characters (which
can be as long as 763 bytes), and MUST have been processed using [SASLprep](https://datatracker.ietf.org/doc/html/rfc4013).

### [Section 15.8](https://datatracker.ietf.org/doc/html/rfc5389#section-15.8) Attribute NONCE

It contains a sequence of qdtext or quoted-pair, which are defined in
[RFC 3261](https://datatracker.ietf.org/doc/html/rfc3261).
Note that this means that the NONCE attribute will not contain actual quote characters.

It MUST be less than 128 characters (which can be as long as 763 bytes).

### [Section 15.9](https://datatracker.ietf.org/doc/html/rfc5389#section-15.9) Attribute UNKNOWN-ATTRIBUTES

The attribute contains a list of 16-bit values, each of which
represents an attribute type that was not understood by the server.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 1 Type           |     Attribute 2 Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 3 Type           |     Attribute 4 Type       ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

In RFC 3489, this field was padded to 32 by duplicating the last attribute.
In this version of the specification, the normal padding rules for attributes are used instead.

### [Section 15.10](https://datatracker.ietf.org/doc/html/rfc5389#section-15.10) Attribute SOFTWARE

The value of SOFTWARE is variable length. It MUST be a [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629)
encoded sequence of less than 128 characters (which can be as long as 763 bytes).

### [Section 15.11](https://datatracker.ietf.org/doc/html/rfc5389#section-15.11) Attribute ALTERNATE-SERVER

The value is encoded in the same way as MAPPED-ADDRESS, and thus refers to a
single server by IP address. The IP address family MUST be identical to that of the source IP address of the request.

### [Section 18.2](https://datatracker.ietf.org/doc/html/rfc5389#section-18.2) Attribute types registry

The initial STUN Attributes types are:

Comprehension-required range (`0x0000`-`0x7FFF`):
```text
0x0000: (Reserved)
0x0001: MAPPED-ADDRESS
0x0002: (Reserved; was RESPONSE-ADDRESS)
0x0003: (Reserved; was CHANGE-ADDRESS)
0x0004: (Reserved; was SOURCE-ADDRESS)
0x0005: (Reserved; was CHANGED-ADDRESS)
0x0006: USERNAME
0x0007: (Reserved; was PASSWORD)
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: (Reserved; was REFLECTED-FROM)
0x0014: REALM
0x0015: NONCE
0x0020: XOR-MAPPED-ADDRESS
```

Comprehension-optional range (`0x8000`-`0xFFFF`)
```text
0x8022: SOFTWARE
0x8023: ALTERNATE-SERVER
0x8028: FINGERPRINT
```

## [RFC 5245](https://datatracker.ietf.org/doc/html/rfc5245)

### [Section 19.1](https://datatracker.ietf.org/doc/html/rfc5245#section-19.1) New attributes

This specification defines four new attributes, PRIORITY, USE-CANDIDATE, ICE-CONTROLLED, and ICE-CONTROLLING.

The PRIORITY attribute indicates the priority that is to be
associated with a peer reflexive candidate, should one be discovered
by this check. It is a 32-bit unsigned integer, and has an attribute
value of 0x0024.

The USE-CANDIDATE attribute indicates that the candidate pair
resulting from this check should be used for transmission of media.
The attribute has no content (the Length field of the attribute is
zero); it serves as a flag. It has an attribute value of 0x0025.

The ICE-CONTROLLED attribute is present in a Binding request and
indicates that the client believes it is currently in the controlled
role. The content of the attribute is a 64-bit unsigned integer in
network byte order, which contains a random number used for tie-
breaking of role conflicts.

The ICE-CONTROLLING attribute is present in a Binding request and
indicates that the client believes it is currently in the controlling
role. The content of the attribute is a 64-bit unsigned integer in
network byte order, which contains a random number used for tie-
breaking of role conflicts.

### [Section 19.12](https://datatracker.ietf.org/doc/html/rfc5245#section-19.2) New error codes

This specification defines a single error response code:

 - `487 (Role Conflict)` The Binding request contained either the ICE-CONTROLLING or ICE-CONTROLLED attribute, indicating a role that
conflicted with the server. The server ran a tie-breaker based on
the tie-breaker value in the request and determined that the
client needs to switch roles.

## [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)

### [Section 7.2](https://datatracker.ietf.org/doc/html/rfc5780#section-7.2) Attribute CHANGE-REQUEST

The attribute is 32 bits long, although only two bits (A and B) are used:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The meanings of the flags are:

A: This is the "change IP" flag. If true, it requests the server to
send the Binding Response with a different IP address than the one
the Binding Request was received on.

B: This is the "change port" flag. If true, it requests the server
to send the Binding Response with a different port than the one
the Binding Request was received on.

### [Section 7.3](https://datatracker.ietf.org/doc/html/rfc5780#section-7.3) Attribute RESPONSE-ORIGIN

The RESPONSE-ORIGIN attribute is inserted by the server and indicates the source IP address and port the response was sent from.

*Editor's note:* The RFC does not explicity specify whether this attribute follows the MAPPED-ADDERESS or XOR-MAPPED-ADDRESS semantics.
However, it can be inferred (guessed) from Section 7.2 that the attribute should follow the MAPPED-ADDRESS semantics.

### [Section 7.4](https://datatracker.ietf.org/doc/html/rfc5780#section-7.4) Attribute OTHER-ADDRESS

It informs the client of the source IP address and port that would be used if the client requested the "change IP" and "change port" behavior.

OTHER-ADDRESS uses the same attribute number as CHANGED-ADDRESS from
RFC 3489 because it is simply a new name with the same
semantics as CHANGED-ADDRESS. It has been renamed to more clearly
indicate its function.

*Editor's note*: **in my opinion**, the paragraph above is incorrect.
This is because the attribute type of the CHANGED-ADDRESS attriubute in RFC 3489 equals `0x0005`, whereas attribute type of the OTHER-ADDRESS attribute equals `0x802c`.
For this reason I believe that the paragraph above should be be dismissed.

### [Section 7.5](https://datatracker.ietf.org/doc/html/rfc5780#section-7.5) Attribute RESPONSE-PORT

RESPONSE-PORT is a 16-bit unsigned integer in network byte order followed by 2 bytes of padding.
Allowable values of RESPONSE-PORT are `0`-`65536`.

### [Section 7.6](https://datatracker.ietf.org/doc/html/rfc5780#section-7.6) Attribute PADDING

PADDING consists entirely of a free-form string, the value of which does not matter.

### [Section 9.1](https://datatracker.ietf.org/doc/html/rfc5780#section-9.1) Attribute types registry

This specification defines several new STUN attributes. IANA has
added these new protocol elements to the "STUN Attributes" registry.

```text
0x0003: CHANGE-REQUEST
0x0027: RESPONSE-PORT
0x0026: PADDING
0x8027: CACHE-TIMEOUT
0x802B: RESPONSE-ORIGIN
0x802C: OTHER-ADDRESS
```

*Editor's note:* No other RFC metions the CACHE-TIMEOUT attribute; it is only metioned in an IETF's [Draft document ver. 6 of RFC 5780](https://datatracker.ietf.org/doc/html/draft-ietf-behave-nat-behavior-discovery-06).
The description of the attribute is present in [Section 7.8](https://datatracker.ietf.org/doc/html/draft-ietf-behave-nat-behavior-discovery-06#section-7.8) of the Draft document.
This entire section is removed in [version 7](https://datatracker.ietf.org/doc/html/draft-ietf-behave-nat-behavior-discovery-07) of the Draft document and does not reappear again either in subsequent drafts, nor in the final RFC 5780 document.
Even though the description is missing from the RFC, several mentions of the attribute are scattered throughout the document, and hence the attribute is listed here as well.

The relelant excerpt from the description from the Draft document ver. 6 is thus pasted below, even though it formally does not belong to RFC 5780.

> The CACHE-TIMEOUT is used in Binding Requests and Responses. It indicates the time duration (in seconds) that the server will cache the source address and USERNAME of an original binding request that will later by followed by a request from a different source address with a XOR-RESPONSE-TARGET asking that a response be reflected to the source address of the original binding request.
 The client inserts a value in CACHE-TIMEOUT into the Binding Request indicating the amount of time it would like the server to cache that information. The server responds with a CACHE-TIMEOUT in its Binding Response providing a prediction of how long it will cache that information.

*Editor's note, again:* you may notice that there is no mention of byte order, signed/unsigned format, or padding.
This is not by the editor's omission, these details are indeed missing from the original Draft document.

## [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766)

### [Section 13](https://datatracker.ietf.org/doc/html/rfc5766#section-13) New STUN methods

This section lists the codepoints for the new STUN methods defined in
this specification.

```text
0x003: Allocate         (only request/response semantics defined)
0x004: Refresh          (only request/response semantics defined)
0x006: Send             (only indication semantics defined)
0x007: Data             (only indication semantics defined)
0x008: CreatePermission (only request/response semantics defined)
0x009: ChannelBind      (only request/response semantics defined)
```

### [Section 14](https://datatracker.ietf.org/doc/html/rfc5766#section-14) New STUN attributes

This STUN extension defines the following new attributes:

```text
0x000C: CHANNEL-NUMBER
0x000D: LIFETIME
0x0010: Reserved (was BANDWIDTH)
0x0012: XOR-PEER-ADDRESS
0x0013: DATA
0x0016: XOR-RELAYED-ADDRESS
0x0018: EVEN-PORT
0x0019: REQUESTED-TRANSPORT
0x001A: DONT-FRAGMENT
0x0021: Reserved (was TIMER-VAL)
0x0022: RESERVATION-TOKEN
```

Any attribute whose length is not a multiple of 4 bytes MUST be immediately followed by 1 to 3 padding bytes.

### [Section 14.1](https://datatracker.ietf.org/doc/html/rfc5766#section-14.1) Attribute CHANNEL-NUMBER

The CHANNEL-NUMBER attribute contains the number of the channel. The
value portion of this attribute is 4 bytes long and consists of a 16-
bit unsigned integer, followed by a two-octet RFFU (Reserved For
Future Use) field, which MUST be set to 0 on transmission and MUST be
ignored on reception.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Channel Number         |         RFFU = 0              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### [Section 14.2](https://datatracker.ietf.org/doc/html/rfc5766#section-14.2) Attribute LIFETIME

The LIFETIME attribute represents the duration for which the server
will maintain an allocation in the absence of a refresh. The value
portion of this attribute is 4-bytes long and consists of a 32-bit
unsigned integral value representing the number of seconds remaining
until expiration.

### [Section 14.3](https://datatracker.ietf.org/doc/html/rfc5766#section-14.3) Attribute XOR-PEER-ADDRESS

The XOR-PEER-ADDRESS specifies the address and port of the peer as
seen from the TURN server. (For example, the peer's server-reflexive
transport address if the peer is behind a NAT.) It is encoded in the
same way as XOR-MAPPED-ADDRESS in RFC 5389.


### [Section 14.4](https://datatracker.ietf.org/doc/html/rfc5766#section-14.4) Attribute DATA

The DATA attribute is present in all Send and Data indications. The
value portion of this attribute is variable length and consists of
the application data (that is, the data that would immediately follow
the UDP header if the data was been sent directly between the client
and the peer). If the length of this attribute is not a multiple of
4, then padding must be added after this attribute.

### [Section 14.5](https://datatracker.ietf.org/doc/html/rfc5766#section-14.5) Attribute XOR-RELAYED-ADDRESS

The XOR-RELAYED-ADDRESS is present in Allocate responses. It
specifies the address and port that the server allocated to the
client. It is encoded in the same way as XOR-MAPPED-ADDRESS in RFC 5389.

### [Section 14.6](https://datatracker.ietf.org/doc/html/rfc5766#section-14.6) Attribute EVEN-PORT

This attribute allows the client to request that the port in the
relayed transport address be even, and (optionally) that the server
reserve the next-higher port number. The value portion of this
attribute is 1 byte long. Its format is:

```text
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R|    RFFU     |
+-+-+-+-+-+-+-+-+
```

The value contains a single 1-bit flag:

R: If 1, the server is requested to reserve the next-higher port
number (on the same IP address) for a subsequent allocation. If
0, no such reservation is requested.

The other 7 bits of the attribute's value must be set to zero on
transmission and ignored on reception.

Since the length of this attribute is not a multiple of 4, padding
must immediately follow this attribute.

### [Section 14.7](https://datatracker.ietf.org/doc/html/rfc5766#section-14.7) Attribute REQUESTED-TRANSPORT

This attribute is used by the client to request a specific transport
protocol for the allocated transport address. The value of this
attribute is 4 bytes with the following format:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Protocol   |                    RFFU                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Protocol field specifies the desired protocol. The codepoints
used in this field are taken from those allowed in the Protocol field
in the IPv4 header and the NextHeader field in the IPv6 header
[Protocol-Numbers](https://datatracker.ietf.org/doc/html/rfc5766#ref-Protocol-Numbers). This specification only allows the use of
codepoint 17 (User Datagram Protocol).

The RFFU field MUST be set to zero on transmission and MUST be
ignored on reception. It is reserved for future uses.

### [Section 14.8](https://datatracker.ietf.org/doc/html/rfc5766#section-14.8) Attribute DONT-FRAGMENT

This attribute has no value part and thus the attribute length field is 0.

### [Section 14.9](https://datatracker.ietf.org/doc/html/rfc5766#section-14.9) Attribute RESERVATION-TOKEN

The attribute value is 8 bytes and contains the token value.

### [Section 15](https://datatracker.ietf.org/doc/html/rfc5766#section-15) New STUN Error Response Codes

This document defines the following new error response codes:

 - `403 (Forbidden)` The request was valid but cannot be performed due
to administrative or similar restrictions.


 - `437 (Allocation Mismatch)` A request was received by the server that
requires an allocation to be in place, but no allocation exists,
or a request was received that requires no allocation, but an
allocation exists.

 - `441 (Wrong Credentials)` The credentials in the (non-Allocate)
request do not match those used to create the allocation.

 - `442 (Unsupported Transport Protocol)` The Allocate request asked the
server to use a transport protocol between the server and the peer
that the server does not support. NOTE: This does NOT refer to
the transport protocol used in the 5-tuple.


 - `486 (Allocation Quota Reached)` No more allocations using this
username can be created at the present time.


 - `508 (Insufficient Capacity)` The server is unable to carry out the
request due to some capacity limit being reached. In an Allocate
response, this could be due to the server having no more relayed
transport addresses available at that time, having none with the
requested properties, or the one that corresponds to the specified
reservation token is not available.

## [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)

### [Section 5](https://datatracker.ietf.org/doc/html/rfc8489#section-5) Message header

All STUN messages comprise a 20-byte header followed by zero or more
attributes. The STUN header contains a STUN message type, message
length, magic cookie, and transaction ID.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Transaction ID (96 bits)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The STUN Message Type field is decomposed further into the following
structure:

```text
 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|M|M|M|M|M|C|M|M|M|C|M|M|M|M|
|B|A|9|8|7|1|6|5|4|0|3|2|1|0|
+--+--+-+-+-+-+-+-+-+-+-+-+-+
```

Here the bits in the STUN Message Type field are shown as most
significant (MB) through least significant (M0). MB through M0
represent a 12-bit encoding of the method. C1 and C0 represent a
2-bit encoding of the class. A class of `0b00` is a request, a class
of `0b01` is an indication, a class of `0b10` is a success response, and
a class of `0b11` is an error response. This specification defines a
single method, Binding. The method and class are orthogonal, so that
for each method, a request, success response, error response, and
indication are possible for that method. Extensions defining new
methods MUST indicate which classes are permitted for that method.

The Magic Cookie field MUST contain the fixed value `0x2112A442` in
network byte order.

The Transaction ID is a 96-bit identifier, used to uniquely identify
STUN transactions.

The message length MUST contain the size of the message in bytes, not
including the 20-byte STUN header. Since all STUN attributes are
padded to a multiple of 4 bytes, the last 2 bits of this field are
always zero.


### [Section 14](https://datatracker.ietf.org/doc/html/rfc8489#section-14) STUN Attributes

After the STUN header are zero or more attributes. Each attribute
MUST be TLV encoded, with a 16-bit type, 16-bit length, and value.
Each STUN attribute MUST end on a 32-bit boundary. As mentioned
above, all fields in an attribute are transmitted most significant
bit first.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type                  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Value (variable)                     ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The value in the Length field MUST contain the length of the Value
part of the attribute, prior to padding, measured in bytes. Since
STUN aligns attributes on 32-bit boundaries, attributes whose content
is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
padding so that its value contains a multiple of 4 bytes. The
padding bits MUST be set to zero on sending and MUST be ignored by
the receiver.

### [Section 14.1](https://datatracker.ietf.org/doc/html/rfc8489#section-14.1) Attribute MAPPED-ADDRESS

The MAPPED-ADDRESS attribute indicates a reflexive transport address
of the client. It consists of an 8-bit address family and a 16-bit
port, followed by a fixed-length value representing the IP address.
If the address family is IPv4, the address MUST be 32 bits. If the
address family is IPv6, the address MUST be 128 bits. All fields
must be in network byte order.

The format of the MAPPED-ADDRESS attribute is:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0|    Family     |           Port                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                 Address (32 bits or 128 bits)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
The address family can take on the following values:

```text
0x01: IPv4
0x02: IPv6
```

The first 8 bits of the MAPPED-ADDRESS MUST be set to 0 and MUST be
ignored by receivers. These bits are present for aligning parameters
on natural 32-bit boundaries.

### [Section 14.2](https://datatracker.ietf.org/doc/html/rfc8489#section-14.2) Attribute XOR-MAPPED-ADDRESS

The format of the XOR-MAPPED-ADDRESS is:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0 0 0 0 0 0 0|    Family     |           Port                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                 Address (32 bits or 128 bits)                 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Family field represents the IP address family and is encoded
identically to the Family field in MAPPED-ADDRESS.

Port is computed by XOR'ing the mapped port with the most
significant 16 bits of the magic cookie. If the IP address family is
IPv4, Address is computed by XOR'ing the mapped IP address with the
magic cookie. If the IP address family is IPv6, Address is
computed by XOR'ing the mapped IP address with the concatenation of
the magic cookie and the 96-bit transaction ID. In all cases, the
XOR operation works on its inputs in network byte order (that is, the
order they will be encoded in the message).

### [Section 14.3](https://datatracker.ietf.org/doc/html/rfc8489#section-14.3) Attribute USERNAME

The value of USERNAME is a variable-length value containing the
authentication username. It MUST contain a [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629) 
sequence of fewer than 509 bytes and MUST have been processed using
the [OpaqueString profile](https://datatracker.ietf.org/doc/html/rfc8265).
A compliant implementation MUST be able to parse a UTF-8-encoded sequence of 763 or fewer octets to be compatible with RFC 5389.

### [Section 14.4](https://datatracker.ietf.org/doc/html/rfc8489#section-14.4) Attribute USERHASH

The value of USERHASH has a fixed length of 32 bytes.

### [Section 14.5](https://datatracker.ietf.org/doc/html/rfc8489#section-14.5) Attribute MESSAGE-INTEGRITY

Since it uses the SHA-1 hash, the HMAC will be 20 bytes.

### [Section 14.6](https://datatracker.ietf.org/doc/html/rfc8489#section-14.6) Attribute MESSAGE-INTEGRITY-SHA256

The value will be at most 32 bytes, but it MUST be at least 16 bytes and MUST be a multiple of 4 bytes.
The value must be the full 32 bytes unless the STUN Usage explicitly specifies that truncation is allowed.

### [Section 14.7](https://datatracker.ietf.org/doc/html/rfc8489#section-14.7) Attribute FINGERPRINT

The value of the attribute is computed as the CRC-32 of the STUN message up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with the 32-bit value `0x5354554E`.

### [Section 14.8](https://datatracker.ietf.org/doc/html/rfc8489#section-14.8) Attribute ERROR-CODE

The ERROR-CODE attribute is used in error response messages. It
contains a numeric error code value in the range of 300 to 699 plus a
textual reason phrase encoded in [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629); it is also
consistent in its code assignments and semantics with [SIP](https://datatracker.ietf.org/doc/html/rfc3489#ref-10) and [HTTP](https://datatracker.ietf.org/doc/html/rfc3489#ref-15).
The reason phrase is meant for diagnosticpurposes and can be anything appropriate for the error code.
Recommended reason phrases for the defined error codes are included
in the IANA registry for error codes. The reason phrase MUST be a
UTF-8-encoded sequence of fewer than 128 characters (which
can be as long as 509 bytes when encoding them or 763 bytes when
decoding them).

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved, should be 0         |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Reason Phrase (variable)                   ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Reserved bits SHOULD be 0 and are for alignment on 32-bit
boundaries. Receivers MUST ignore these bits. The Class represents
the hundreds digit of the error code. The value MUST be between 3
and 6. The Number represents the binary encoding of the error code
modulo 100, and its value MUST be between 0 and 99.

The following error codes, along with their recommended reason
phrases, are defined:

 - `300 Try Alternate` The client should contact an alternate server for
this request. This error response MUST only be sent if the
request included either a USERNAME or USERHASH attribute and a
valid MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute;
otherwise, it MUST NOT be sent and error code 400 (Bad Request)
is suggested. This error response MUST be protected with the
MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, and
receivers MUST validate the MESSAGE-INTEGRITY or MESSAGE-
INTEGRITY-SHA256 of this response before redirecting themselves
to an alternate server.


 - `400 Bad Request` The request was malformed. The client SHOULD NOT
retry the request without modification from the previous
attempt. The server may not be able to generate a valid
MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 for this error, so
the client MUST NOT expect a valid MESSAGE-INTEGRITY or MESSAGE-
INTEGRITY-SHA256 attribute on this response.


 - `401 Unauthenticated` The request did not contain the correct
credentials to proceed. The client should retry the request
with proper credentials.


 - `420 Unknown Attribute` The server received a STUN packet containing
a comprehension-required attribute that it did not understand.
The server MUST put this unknown attribute in the UNKNOWN-
ATTRIBUTE attribute of its error response.


 - `438 Stale Nonce` The NONCE used by the client was no longer valid.
The client should retry, using the NONCE provided in the
response.


 - `500 Server Error` The server has suffered a temporary error. The
client should try again.


### [Section 14.9](https://datatracker.ietf.org/doc/html/rfc8489#section-14.9) Attribute REALM

It MUST be a UTF-8-encoded sequence of fewer than 128 characters (which can be as long
as 509 bytes when encoding them and as long as 763 bytes when
decoding them) and MUST have been processed using the [OpaqueString profile](https://datatracker.ietf.org/doc/html/rfc8265).

### [Section 14.10](https://datatracker.ietf.org/doc/html/rfc8489#section-14.10) Attribute NONCE

Note that this means that the NONCE attribute will not
contain the actual surrounding quote characters. The NONCE attribute
MUST be fewer than 128 characters (which can be as long as 509 bytes
when encoding them and a long as 763 bytes when decoding them).

### [Section 14.11](https://datatracker.ietf.org/doc/html/rfc8489#section-14.11) Attribute PASSWORD-ALGORITHMS

The algorithm number is a 16-bit value. The parameters start with the length (prior to
padding) of the parameters as a 16-bit value, followed by the
parameters that are specific to each algorithm. The parameters are
padded to a 32-bit boundary, in the same manner as an attribute.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Algorithm 1           | Algorithm 1 Parameters Length |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Algorithm 1 Parameters (variable)         ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Algorithm 2           | Algorithm 2 Parameters Length |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Algorithm 2 Parameters (variable)         ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                              ..
```

### [Section 14.12](https://datatracker.ietf.org/doc/html/rfc8489#section-14.12) Attribute PASSWORD-ALGORITHM

The algorithm number is a 16-bit value. The parameters starts with the length (prior to
padding) of the parameters as a 16-bit value, followed by the
parameters that are specific to the algorithm. The parameters are
padded to a 32-bit boundary, in the same manner as an attribute.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Algorithm            |  Algorithm Parameters Length  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Algorithm Parameters (variable)           ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### [Section 14.13](https://datatracker.ietf.org/doc/html/rfc8489#section-14.13) Attribute UNKNOWN-ATTRIBUTES

The attribute contains a list of 16-bit values, each of which
represents an attribute type that was not understood by the server.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 1 Type         |       Attribute 2 Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Attribute 3 Type         |       Attribute 4 Type       ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### [Section 14.14](https://datatracker.ietf.org/doc/html/rfc8489#section-14.14) Attribute SOFTWARE

The value of SOFTWARE is variable length. It MUST be a [UTF-8](https://datatracker.ietf.org/doc/html/rfc3629) sequence of fewer than 128 characters (which can be as long as 509 when encoding them and as long as 763 bytes when decoding them).

### [Section 14.15](https://datatracker.ietf.org/doc/html/rfc8489#section-14.15) Attribute ALTERNATE-SERVER

It is encoded in the same way as MAPPED-ADDRESS and thus refers to a
single server by IP address.

### [Section 14.16](https://datatracker.ietf.org/doc/html/rfc8489#section-14.16) Attribute ALTERNATE-DOMAIN

The value of ALTERNATE-DOMAIN is variable length. It MUST be a valid
[DNS name](https://datatracker.ietf.org/doc/html/rfc1123) (including [A-labels](https://datatracker.ietf.org/doc/html/rfc5890)) of 255 or fewer ASCII characters.

### [Section 18.3.1](https://datatracker.ietf.org/doc/html/rfc8489#section-18.3.1) Updates STUN attributes

Comprehension-required range (`0x0000`-`0x7FFF`):
```text
0x0000: Reserved
0x0001: MAPPED-ADDRESS
0x0002: Reserved; was RESPONSE-ADDRESS prior to [RFC5389]
0x0003: Reserved; was CHANGE-REQUEST prior to [RFC5389]
0x0004: Reserved; was SOURCE-ADDRESS prior to [RFC5389]
0x0005: Reserved; was CHANGED-ADDRESS prior to [RFC5389]
0x0006: USERNAME
0x0007: Reserved; was PASSWORD prior to [RFC5389]
0x0008: MESSAGE-INTEGRITY
0x0009: ERROR-CODE
0x000A: UNKNOWN-ATTRIBUTES
0x000B: Reserved; was REFLECTED-FROM prior to [RFC5389]
0x0014: REALM
0x0015: NONCE
0x0020: XOR-MAPPED-ADDRESS
```

Comprehension-optional range (`0x8000`-`0xFFFF`)
```text
0x8022: SOFTWARE
0x8023: ALTERNATE-SERVER
0x8028: FINGERPRINT
```

### [Section 18.3.2](https://datatracker.ietf.org/doc/html/rfc8489#section-18.3.2) New STUN attributes

IANA has added the following attribute to the "STUN Attributes"
registry:

Comprehension-required range (`0x0000`-`0x7FFF`):
```text
0x001C: MESSAGE-INTEGRITY-SHA256
0x001D: PASSWORD-ALGORITHM
0x001E: USERHASH
```

Comprehension-optional range (`0x8000`-`0xFFFF`):
```text
0x8002: PASSWORD-ALGORITHMS
0x8003: ALTERNATE-DOMAIN
```

### [Section 18.5](https://datatracker.ietf.org/doc/html/rfc8489#section-18.5) STUN Password Algorithms registry

A password algorithm is a hex number in the range `0x0000`-`0xFFFF`.

The initial contents of the "Password Algorithm" registry are as
follows:

```text
0x0000: Reserved
0x0001: MD5
0x0002: SHA-256
0x0003-0xFFFF: Unassigned
```

### [Section 18.5.1.1](https://datatracker.ietf.org/doc/html/rfc8489#section-18.5.1.1) MD5 algorithm details

The key length is 16 bytes, and the parameters value is empty.

key = MD5(username ":" OpaqueString(realm) ":" OpaqueString(password))

### [Section 18.5.1.2](https://datatracker.ietf.org/doc/html/rfc8489#section-18.5.1.2) SHA-256 algorithm details

The key length is 32 bytes, and the parameters value is empty.

key = SHA-256(username ":" OpaqueString(realm) ":" OpaqueString(password))

## [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)

### [Section 16.1](https://datatracker.ietf.org/doc/html/rfc8445#section-16.1) New STUN attributes

This specification defines four STUN attributes: PRIORITY,
USE-CANDIDATE, ICE-CONTROLLED, and ICE-CONTROLLING.

The PRIORITY attribute indicates the priority that is to be
associated with a peer-reflexive candidate, if one will be discovered
by this check. It is a 32-bit unsigned integer and has an attribute
value of `0x0024`.

The USE-CANDIDATE attribute indicates that the candidate pair
resulting from this check will be used for transmission of data. The
attribute has no content (the Length field of the attribute is zero);
it serves as a flag. It has an attribute value of `0x0025`.

The ICE-CONTROLLED attribute is present in a Binding request. The
attribute indicates that the client believes it is currently in the
controlled role. The content of the attribute is a 64-bit unsigned
integer in network byte order, which contains a random number.

The ICE-CONTROLLING attribute is present in a Binding request. The
attribute indicates that the client believes it is currently in the
controlling role. The content of the attribute is a 64-bit unsigned
integer in network byte order, which contains a random number.

### [Section 16.2](https://datatracker.ietf.org/doc/html/rfc8445#section-16.2) New STUN Error Response Codes

This specification defines a single error-response code:

 - `487 (Role Conflict)` The Binding request contained either the ICE-
CONTROLLING or ICE-CONTROLLED attribute, indicating an ICE role
that conflicted with the server. The remote server compared the
tiebreaker values of the client and the server and determined that
the client needs to switch roles.


### [Section 20.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-20.1) STUN Attributes

IANA has registered four STUN attributes:

```text
0x0024: PRIORITY
0x0025: USE-CANDIDATE
0x8029: ICE-CONTROLLED
0x802A: ICE-CONTROLLING
```


## [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656)


### [Section 17](https://datatracker.ietf.org/doc/html/rfc8656#section-17) New STUN Methods

```text
+-------+------------------+-------------------------------------------+
| 0x003 | Allocate         | (only request/response semantics defined) |
+-------+------------------+-------------------------------------------+
| 0x004 | Refresh          | (only request/response semantics defined) |
+-------+------------------+-------------------------------------------+
| 0x006 | Send             | (only indication semantics defined)       |
+-------+------------------+-------------------------------------------+
| 0x007 | Data             | (only indication semantics defined)       |
+-------+------------------+-------------------------------------------+
| 0x008 | CreatePermission | (only request/response semantics defined) |
+-------+------------------+-------------------------------------------+
| 0x009 | ChannelBind      | (only request/response semantics defined) |
+-------+------------------+-------------------------------------------+
```

### [Section 18](https://datatracker.ietf.org/doc/html/rfc8656#section-18) New STUN attributes

This STUN extension defines the following attributes:

```text
+--------+---------------------------+
| 0x000C | CHANNEL-NUMBER            |
+--------+---------------------------+
| 0x000D | LIFETIME                  |
+--------+---------------------------+
| 0x0010 | Reserved (was BANDWIDTH)  |
+--------+---------------------------+
| 0x0012 | XOR-PEER-ADDRESS          |
+--------+---------------------------+
| 0x0013 | DATA                      |
+--------+---------------------------+
| 0x0016 | XOR-RELAYED-ADDRESS       |
+--------+---------------------------+
| 0x0017 | REQUESTED-ADDRESS-FAMILY  |
+--------+---------------------------+
| 0x0018 | EVEN-PORT                 |
+--------+---------------------------+
| 0x0019 | REQUESTED-TRANSPORT       |
+--------+---------------------------+
| 0x001A | DONT-FRAGMENT             |
+--------+---------------------------+
| 0x0021 | Reserved (was TIMER-VAL)  |
+--------+---------------------------+
| 0x0022 | RESERVATION-TOKEN         |
+--------+---------------------------+
| 0x8000 | ADDITIONAL-ADDRESS-FAMILY |
+--------+---------------------------+
| 0x8001 | ADDRESS-ERROR-CODE        |
+--------+---------------------------+
| 0x8004 | ICMP                      |
+--------+---------------------------+
```

### [Section 18.1](https://datatracker.ietf.org/doc/html/rfc8656#section-18.1) Attribute CHANNEL-NUMBER

The CHANNEL-NUMBER attribute contains the number of the channel. The
value portion of this attribute is 4 bytes long and consists of a
16-bit unsigned integer followed by a two-octet RFFU (Reserved For
Future Use) field, which MUST be set to 0 on transmission and MUST be
ignored on reception.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Channel Number         |         RFFU = 0              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### [Section 18.2](https://datatracker.ietf.org/doc/html/rfc8656#section-18.2) Attribute LIFETIME

The value portion of this attribute is 4 bytes long and consists of a 32-bit unsigned integral
value representing the number of seconds remaining until expiration.

### [Section 18.3](https://datatracker.ietf.org/doc/html/rfc8656#section-18.3) Attribute XOR-PEER-ADDRESS

It is encoded in the same way as the XOR-MAPPED-ADDRESS attribute RFC 8489.

### [Section 18.4](https://datatracker.ietf.org/doc/html/rfc8656#section-18.4) Attribute DATA

The value portion of this attribute is variable length
and consists of the application data (that is, the data that would
immediately follow the UDP header if the data was sent directly
between the client and the peer).

If the length of this attribute is not a multiple of 4, then padding must be added after this attribute.

### [Section 18.5](https://datatracker.ietf.org/doc/html/rfc8656#section-18.5) Attribute XOR-RELAYED-ADDRESS

It is encoded in the same way as the XOR-MAPPED-ADDRESS attribute RFC 8489.

### [Section 18.6](https://datatracker.ietf.org/doc/html/rfc8656#section-18.6) Attribute REQUESTED-ADDRESS-FAMILY

The value of this attribute is 4 bytes with the following format:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Family    |            Reserved                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Family: There are two values defined for this field and specified in
Section 14.1 of RFC 8489: 
 - `0x01` for IPv4 addresses 
 - `0x02` for IPv6 addresses

Reserved: At this point, the 24 bits in the Reserved field MUST be
set to zero by the client and MUST be ignored by the server.

### [Section 18.7](https://datatracker.ietf.org/doc/html/rfc8656#section-18.7) Attribute EVEN-PORT

This attribute allows the client to request that the port in the
relayed transport address be even and (optionally) that the server
reserve the next-higher port number. The value portion of this
attribute is 1 byte long. Its format is:

```text
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R|    RFFU     |
+-+-+-+-+-+-+-+-+
```

The value contains a single 1-bit flag:

R: If 1, the server is requested to reserve the next-higher port number (on the same IP address) for a subsequent allocation.
If 0, no such reservation is requested.

RFFU: Reserved For Future Use.

Since the length of this attribute is not a multiple of 4, padding
must immediately follow this attribute.

### [Section 18.8](https://datatracker.ietf.org/doc/html/rfc8656#section-18.8) Attribute REQUESTED-TRANSPORT

The value of this attribute is 4 bytes with the following format:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Protocol   |                    RFFU                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The Protocol field specifies the desired protocol. The code points
used in this field are taken from those allowed in the Protocol field
in the IPv4 header and the NextHeader field in the IPv6 header
[PROTOCOL-NUMBERS](https://datatracker.ietf.org/doc/html/rfc8656#ref-PROTOCOL-NUMBERS).
This specification only allows the use of code
point 17 (User Datagram Protocol).

### [Section 18.9](https://datatracker.ietf.org/doc/html/rfc8656#section-18.9) Attribute DONT-FRAGMENT

This attribute has no value part, and thus, the attribute length field is 0.

### [Section 18.10](https://datatracker.ietf.org/doc/html/rfc8656#section-18.10) Attribute RESERVATION-TOKEN

The attribute value is 8 bytes and contains the token value.

### [Section 18.11](https://datatracker.ietf.org/doc/html/rfc8656#section-18.11) Attribute ADDITIONAL-ADDRESS-FAMILY

It is encoded in the same way as the REQUESTED-ADDRESS-FAMILY attribute.
The attribute value of 0x02 (IPv6 address) is the only valid value in Allocate request.

### [Section 18.12](https://datatracker.ietf.org/doc/html/rfc8656#section-18.12) Attribute ADDRESS-ERROR-CODE

The value portion of this attribute is variable length with the following format:

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Family     |        Reserved         |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Reason Phrase (variable)                  ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Family: There are two values defined for this field and specified in
Section 14.1 of RFC 8489: 0x01 for IPv4 addresses and 0x02 for
IPv6 addresses.

Reserved: At this point, the 13 bits in the Reserved field MUST be
set to zero by the server and MUST be ignored by the client.

Class: The Class represents the hundreds digit of the error code and
is defined in Section 14.8 of RFC 8489.

Number: This 8-bit field contains the reason the server cannot
allocate one of the requested address types. The error code
values could be either 440 (Address Family not Supported) or 508
(Insufficient Capacity). The number representation is defined in
Section 14.8 of RFC 8489.

Reason Phrase: The recommended reason phrases for error codes 440
and 508 are explained in Section 19. The reason phrase MUST be a
UTF-8 encoded sequence of less than 128 characters
(which can be as long as 509 bytes when encoding them or 763 bytes
when decoding them).

### [Section 18.13](https://datatracker.ietf.org/doc/html/rfc8656#section-18.13) Attribute IMCP

This attribute is used by servers to signal the reason a UDP packet
was dropped. The following is the format of the ICMP attribute.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved            |  ICMP Type  |    ICMP Code    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Error Data                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Reserved: This field MUST be set to 0 when sent and MUST be ignored
when received.

ICMP Type: The field contains the value of the ICMP type. Its
interpretation depends on whether the ICMP was received over IPv4
or IPv6.

ICMP Code: The field contains the value of the ICMP code. Its
interpretation depends on whether the ICMP was received over IPv4
or IPv6.

Error Data: This field size is 4 bytes long. If the ICMPv6 type is
2 ("Packet too big" message) or ICMPv4 type is 3 (Destination
Unreachable) and Code is 4 (fragmentation needed and DF set), the
Error Data field will be set to the Maximum Transmission Unit of
the next-hop link (Section 3.2 of [RFC4443](https://datatracker.ietf.org/doc/html/rfc4443#section-3.2) and Section 4 of
[RFC1191](https://datatracker.ietf.org/doc/html/rfc1191#section-4)).
For other ICMPv6 types and ICMPv4 types and codes, the Error Data field MUST be set to zero.

### [Section 19](https://datatracker.ietf.org/doc/html/rfc8656#section-19) New STUN error response codes

This document defines the following error response codes:

 - `403 (Forbidden)` The request was valid but cannot be performed due to
administrative or similar restrictions.


 - `437 (Allocation Mismatch)` A request was received by the server that requires an allocation
to be in place, but no allocation exists, or a request was
received that requires no allocation, but an allocation exists.


 - `440 (Address Family not Supported)` The server does not support the address family requested by the
client.


 - `441 (Wrong Credentials)` The credentials in the (non-Allocate) request
do not match those used to create the allocation.


 - `442 (Unsupported Transport Protocol)` The Allocate request asked the server to use a transport protocol
between the server and the peer that the server does not support.
NOTE: This does NOT refer to the transport protocol used in the
5-tuple.


 - `443 (Peer Address Family Mismatch)` A peer address is part of a different address family than that of
the relayed transport address of the allocation.


 - `486 (Allocation Quota Reached)` No more allocations using this username can be created at the
present time.


 - `508 (Insufficient Capacity)` The server is unable to carry out the request due to some capacity
limit being reached. In an Allocate response, this could be due
to the server having no more relayed transport addresses available
at that time, having none with the requested properties, or the
one that corresponds to the specified reservation token is not
available.

## [RFC 6679](https://datatracker.ietf.org/doc/html/rfc6679)

### [Section 7.2.2](https://datatracker.ietf.org/doc/html/rfc6679#section-7.2.2) ECN-CHECK STUN Attribute

The STUN ECN-CHECK attribute contains one field and a flag.
The flag indicates whether the echo field contains a
valid value or not. The field is the ECN echo field and, when valid,
contains the two ECN bits from the packet it echoes back. The ECN-
CHECK attribute is a comprehension optional attribute.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Type                  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved                                      |ECF|V|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

V: Valid (1 bit) ECN Echo value field is valid when set to 1 and
invalid when set 0.

ECF: ECN Echo value field (2 bits) contains the ECN field value of
the STUN packet it echoes back when the field is valid. If
invalid, the content is arbitrary.

Reserved: Reserved bits (29 bits) SHALL be set to 0 on transmission
and SHALL be ignored on reception.


### [Section 10.6](https://datatracker.ietf.org/doc/html/rfc6679#section-10.6)

A new STUN attribute in the comprehension-optional range
under IETF Review (`0x8000`-`0xFFFF`) has been assigned to the ECN-CHECK
STUN attribute (`0x802D`).

## [RFC 7635](https://datatracker.ietf.org/doc/html/rfc7635)

### [Section 6.1](https://datatracker.ietf.org/doc/html/rfc7635#section-6.1) Attribute THIRD-PARTY-AUTHORIZATION

This attribute value contains the STUN server name.

### [Section 6.2](https://datatracker.ietf.org/doc/html/rfc7635#section-6.2) Attribute ACCESS-TOKEN

The token is structured as follows:

```text
struct {
    uint16_t nonce_length;
    opaque nonce[nonce_length];
    opaque {
        uint16_t key_length;
        opaque mac_key[key_length];
        uint64_t timestamp;
        uint32_t lifetime;
    } encrypted_block;
} token;
```

Note: uintN_t means an unsigned integer of exactly N bits. Single-
byte entities containing uninterpreted data are of type 'opaque'.
All values in the token are stored in network byte order.

timestamp: 64-bit unsigned integer field containing a timestamp.
The value indicates the time since January 1, 1970, 00:00 UTC, by
using a fixed-point format. In this format, the integer number of
seconds is contained in the first 48 bits of the field, and the
remaining 16 bits indicate the number of 1/64000 fractions of a
second (Native format - Unix).

lifetime: The lifetime of the access token, in seconds. For
example, the value 3600 indicates one hour. The lifetime value
MUST be greater than or equal to the 'expires_in' parameter
defined in [Section 4.2.2 of RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2), otherwise the resource
server could revoke the token, but the client would assume that
the token has not expired and would not refresh the token.

### [Section 12](https://datatracker.ietf.org/doc/html/rfc7635#section-12) IANA considerations

This document defines the THIRD-PARTY-AUTHORIZATION STUN attribute,
described in Section 6. IANA has allocated the comprehension-
optional codepoint `0x802E` for this attribute.

This document defines the ACCESS-TOKEN STUN attribute, described in
Section 6. IANA has allocated the comprehension-required codepoint
`0x001B` for this attribute.

## [RFC 8016](https://datatracker.ietf.org/doc/html/rfc8016)

### [Section 3.3](https://datatracker.ietf.org/doc/html/rfc8016#section-3.3) Attribute MOBILITY-TICKET

The value of the MOBILITY-TICKET is encrypted and is of variable length.

### [Section 3.4](https://datatracker.ietf.org/doc/html/rfc8016#section-3.4) New STUN error response codes

This document defines the following new error response code:

 - `405 (Mobility Forbidden)` Mobility request was valid but cannot be performed due to administrative or similar restrictions.

### [Section 4](https://datatracker.ietf.org/doc/html/rfc8016#section-4) IANA Considerations

MOBILITY-TICKET (`0x8030`, in the comprehension-optional range)

## [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062#section-6.1)

### [Section 6.1](https://datatracker.ietf.org/doc/html/rfc6062#section-6.1) New STUN Methods

```text
0x000A: Connect
0x000B: ConnectionBind
0x000C: ConnectionAttempt
```

### [Section 6.2](https://datatracker.ietf.org/doc/html/rfc6062#section-6.2) New STUN Attributes
This STUN extension defines the following new attributes:

```text
0x002A: CONNECTION-ID
```

### [Section 6.3](https://datatracker.ietf.org/doc/html/rfc6062#section-6.2.1) Attribute CONNECTION-ID

The CONNECTION-ID attribute uniquely identifies a peer data
connection. It is a 32-bit unsigned integral value.

### [Section 6.4](https://datatracker.ietf.org/doc/html/rfc6062#section-6.3) New STUN error codes

 - `446 (Connection Already Exists)`
 - `447 (Connection Timeout or Failure)`

## [RFC 7982](https://datatracker.ietf.org/doc/html/rfc7982)

### [Section 3.1](https://datatracker.ietf.org/doc/html/rfc7982#section-3.1) Attribute TRANSACTION-TRANSMIT-COUNTER

The format of the value in the TRANSACTION_TRANSMIT_COUNTER attribute
in the request is:

```text
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Reserved (Padding)     |      Req      |     Resp      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The fields are described below:

Req:  Number of times the request is transmitted with the same
transaction ID to the server.

Resp:  Number of times a response with the same transaction ID is
sent from the server.  MUST be set to zero in requests and ignored
by the receiver.

The padding is necessary to hit the 32-bit boundary needed for STUN
attributes.  The padding bits are ignored, but to allow for future
reuse of these bits, they MUST be set to zero.

The IANA-assigned STUN type for the new attribute is `0x8025`.


## Other relevant documents

### [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769)

This document lists sample STUN messages to be used as test vectors.
The samples include both IPv4 and IPv6 cases.
