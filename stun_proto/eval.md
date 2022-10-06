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

##### Struct

A struct represents a collection of other data types (other structs, unions, primitive types, etc.) which reside in memory in the order in which they are specified in the source code.
Each member of this collection must have a uniquely name and type. For example:

```C
struct  {
    
};
```


## Declarative parsers

```C
struct StunMsg {
    uint16_t    type;
    uint16_t    length;
    uint128_t   transaction_id;
    uint8_t     attributes[length];
};
```

### Why bother
This option is attractive because it gives hope that a simple pointer cast is all that is required to parse.

While this is possible, there are a lot of prerequisites:



### Where they work best

When the format does not have arrays. Arrays complicate everything. E.g.

### Raw notes

Pros and cons of different parser types:

#### Repr C'like (declarative)

 - pro: immutable and mutable references implemented together, no need for separate types
 - pro: memory representations really simple if number of elements and their type (incl. size) is known at compile time
 - pro: to_bytes() easy to implement
 - pro: checks are smaller and done only once (eagerly), less branching while reading
 - pro/con: alignment issues may arise, but X86/ARM should be immune to them
 - pro/con: there is a choice of building the fields as [u8; N] (and probably that would eliminate
   the need for `repr(C, packed)`, or building explicitly `be`/`le` types)
 - con: to an extent it has to be early checked (such that we know that no value inside the struct would prompt read/write overflows)
 - con: requires unsafe code
 - con: any field after the first *dynamically sized field* is accessible only via a dynamically calculated pointer,
   not via nice value fields (which brings back the nightmare of double implementations for mutable/immutable variants AND breaks consistency)

#### Getters/Setters (procedural)

 - pro: choice of earger vs lazy evaluation
 - pro: can be implemented with zero unsafe code
 - con: uglier of most types are statically known (type + size), as all access happens via method calls
 - con: impl for mutable/immutable are completely separate, i.e double effort

#### Parser styles

Interfaces

 - like a regular struct
   - field reads like regular fields
   - field writes like regular fields

 - some struct with method calls, like getters/setters, to do read/write ops

 - some struct with callbacks that get triggered certains items/characteristcs

Backings

 - separate memory copy using pitentially many data allocations (i.e. one alloc per any dynamically sized field)
 - separate memory copy using exactly one memory allocation
 - no separate copy but assumes the existence of a biffer that can store the entire struct at once
 - small buf << total length of the message

Philosophies

 - is the data parsed genrally assumed to be correct?
 - is the parsing of invalid data just as common/valuabe to the user as valid data?
 - more genrally: what are the user expectations about reacting to invalid data

#### How parsers are assessed

 - documentation
 - how intuitive it is
 - how compatible it is
   - what requirements it has
     - std
     - alloc
     - its own dependencies
 - how lightweight it is
 - how configurable it is
 - how performant it is
 - how consistent the interface is