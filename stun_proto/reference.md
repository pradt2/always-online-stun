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
0x0001  :  Binding Request
0x0101  :  Binding Response
0x0111  :  Binding Error Response
0x0002  :  Shared Secret Request
0x0102  :  Shared Secret Response
0x0112  :  Shared Secret Error Response
```

The message length is the count, in bytes, of the size of the
message, not including the 20 byte header.

The transaction ID is a 128 bit identifier.  It also serves as salt
to randomize the request and the response.  All responses carry the
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
0x000a: UNKNOWN-ATTRIBUTES
0x000b: REFLECTED-FROM
```

Attributes with values greater than `0x7fff` are optional, which
means that the message can be processed by the client or server even
though the attribute is not understood.  Attributes with values less
than or equal to `0x7fff` are mandatory to understand, which means that
the client or server cannot process the message unless it understands
the attribute.

### [Section 11.2.1](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.1) Attribute MAPPED-ADDRESS

The MAPPED-ADDRESS attribute indicates the mapped IP address and
port.  It consists of an eight bit address family, and a sixteen bit
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
The address family is always 0x01, corresponding to IPv4.  The first
8 bits of the MAPPED-ADDRESS are ignored, for the purposes of
aligning parameters on natural boundaries.  The IPv4 address is 32
bits.

### [Section 11.2.2](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.2) Attribute RESPONSE-ADDRESS

The RESPONSE-ADDRESS attribute indicates where the response to a
Binding Request should be sent.  Its syntax is identical to MAPPED-
ADDRESS.

### [Section 11.2.3](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.3) Attribute CHANGED-ADDRESS

The CHANGED-ADDRESS attribute indicates the IP address and port where
responses would have been sent from if the "change IP" and "change
port" flags had been set in the CHANGE-REQUEST attribute of the
Binding Request.  The attribute is always present in a Binding
Response, independent of the value of the flags.  Its syntax is
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

A: This is the "change IP" flag.  If true, it requests the server
to send the Binding Response with a different IP address than the
one the Binding Request was received on.

B: This is the "change port" flag.  If true, it requests the
server to send the Binding Response with a different port than the
one the Binding Request was received on.

### [Section 11.2.5](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.5) Attribute SOURCE-ADDRESS

The SOURCE-ADDRESS attribute is present in Binding Responses.  It
indicates the source IP address and port that the server is sending
the response from.  Its syntax is identical to that of MAPPED-
ADDRESS.

### [Section 11.2.6](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.6) Attribute USERNAME

The value of USERNAME is a variable length opaque value. Its length
MUST be a multiple of 4 (measured in bytes) in order to guarantee
alignment of attributes on word boundaries.

### [Section 11.2.7](https://datatracker.ietf.org/doc/html/rfc3489#section-11.2.7) Attribute PASSWORD

The value of PASSWORD is a variable length value that is to be used
as a shared secret.  Its length MUST be a multiple of 4 (measured in
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
The lengths of the reason phrases MUST be a multiple of 4 (measured in bytes).  This can
be accomplished by added spaces to the end of the text, if necessary.

```text
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   0                     |Class|     Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Reason Phrase (variable)                 ..
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The class represents the hundreds digit of the response code.  The
value MUST be between 1 and 6.  The number represents the response
code modulo 100, and its value MUST be between 0 and 99.

The following response codes, along with their recommended reason
phrases (in brackets) are defined at this time:

 - `400 (Bad Request)` The request was malformed.  The client should not
retry the request without modification from the previous
attempt.


 - `401 (Unauthorized)` The Binding Request did not contain a MESSAGE-
INTEGRITY attribute.


 - `420 (Unknown Attribute)` The server did not understand a mandatory
attribute in the request.


 - `430 (Stale Credentials)` The Binding Request did contain a MESSAGE-
INTEGRITY attribute, but it used a shared secret that has
expired.  The client should obtain a new shared secret and try
again.


 - `431 (Integrity Check Failure)` The Binding Request contained a
MESSAGE-INTEGRITY attribute, but the HMAC failed verification.
This could be a sign of a potential attack, or client
implementation error.


 - `432 (Missing Username)` The Binding Request contained a MESSAGE-
INTEGRITY attribute, but not a USERNAME attribute.  Both must be
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

The attribute contains the identity (in terms of IP address) of the source where the request came from.  Its purpose is to provide
traceability, so that a STUN server cannot be used as a reflector for denial-of-service attacks.

Its syntax is identical to the MAPPED-ADDRESS attribute.


## [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)

### [Section 6](https://datatracker.ietf.org/doc/html/rfc5389#section-6) Message header

STUN messages are encoded in binary using network-oriented format
(most significant byte or octet first, also commonly known as big-
endian). 

All STUN messages MUST start with a 20-byte header followed by zero
or more Attributes.  The STUN header contains a STUN message type,
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

