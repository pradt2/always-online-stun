# Writing binary parsers

## Binary data format documentation

Before we look at the different approaches to parsing, we should learn how to read 
some of the common documentation formats of binary formats.

### The C-like notation

In the C-like notation, data is represented using concepts like structs, fields, arrays, unions, and primitive types.
All these should should familiar, but let us have a quick refresher anyway:

#### Primitve types
The most fundamental building blocks of any binary format are the *primitive* data types - types so small and simple that it would be pointless to subdivide them into more fine-grained hierarchies.
These types almost universally describe numerical data (or data that is not strictly speaking numeric, but can be represented by a numer - or as Computer Scientists would say: has a numerical representation).

Any primitive data type can be defined using 3 characteristics, as described below.

##### Size

A primitive datatype must define how many bits of memory are needed to store it.
This is so that the computer needs to know how much memory to use to 'remember' a variable of the given type, 
or so that we know how many bits to read (parse) to reconstruct a variable of the given type.

Size is usually expressed in bits, less commonly in bytes. However, despite the elusively available bit-level granularity,
real world formats almost exclusively use sizes that are powers of 2, such as 8 bits, 16 bits, 32 bits, etc.
  
##### Meaning
    
Different data types (even ones with the same size) may choose to use - assign meaning to - bits differently.
The process of encoding the meaning to the binary form, as well as decoding it from bits, must be well defined.

Primitive data types most useful to binary parsing are the numerical data types. They are subdivided into two categories:
  - integer types that can only store whole numbers, e.g. 0, 1, -5, etc...
  - floating-point types that can store whole numbers as well as fractions, e.g -1, 0.75, etc...

Let us start with the easiest one - size. Simply, 

Even though no single universally applied notation exists for the primitive types, binary specifications usually borrow their notation (either literally or with some modifications) from popular programming languages.
A good language to borrow from should have a set of numerical types that:

 * have an obvious binary size (usually incorporated into the type name itself)
 * can either be signed or unsigned
 * 

Below is a table that represents the primitive types most commonly used in binary format specifications:

| Type (size)                    |           C/C++            |   Java    |     Rust      |
|:-------------------------------|:--------------------------:|:---------:|:-------------:|
| boolean (8 bits)               | `bool`, `char`, `uint8_t`  | `boolean` | `bool`, `u8`  |
| unsigned int (8 bits)          | `unsigned char`, `uint8_t` |  `byte`   |     `u8`      |
| unsigned int                   |          &check;           |  &check;  |               |

#### Struct

A struct represents a collection of other data types (other structs, unions, primitive types, etc.) which reside in memory in the order in which they are specified in the source code.
Each member of this collection must have a uniquely name and type. For example:

```C
struct  {
    
};
```


## Declarative parsers

```C
struct StunMsg {
    uint16_t type;
    uint16_t length;
    uint128_t transaction_id;
    uint8_t attributes[length];
};
```

### Why bother
This option is attractive because it gives hope that a simple pointer cast is all that is required to parse.

While this is possible, there are a lot of prerequisites:



### Where they work best

When the format does not have arrays. Arrays complicate everything. E.g.

