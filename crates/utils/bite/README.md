# miden-bite

This crate implements a `serde`-compatible binary encoding which we call BITE, which stands for _Binary Interchange, Tiny Encoding_. As the name implies, it is designed for exchanging data in binary form efficiently - in particular, we aim to use this as the underlying encoding for the Miden package format, and similar use cases.

## Design principles

BITE is designed with the following properties in mind:

* Compact
* Versioned
* Validatable, i.e. the ability to validate the structure of the input without
  needing to deserialize it.
* Use `serde`'s data model to allow for encoding arbitrary Rust data types
* Enable re-use of `serde`'s `Serialize` and `Deserialize` trait impls for both human-readable and BITE-encoded formats.
* Minimally self-describing to allow for supporting `serde` features which require this, e.g. conditionally-skipped fields

## Size reduction techniques

The following are the techniques we use to acheive the goal of compact encoding of arbitrary Rust data structures:

* _Transparent string interning_. This de-duplicates strings that are encoded when serializing a given data structure, storing only a single copy of each unique string, assigning each an integer identifier, and then storing only the identifier at each place the string is used. For structures with many copies of the same string (e.g. an AST where each node holds a reference to the file and line it corresponds to at the source level), this vastly reduces the size of the encoded binary. If all strings in the input data structure are already unique, interning does introduce some minimal overhead; but for our use cases, duplication is far more common than not, and this technique is always beneficial.
* _All integers use variable-length encoding_. Statisically, most integer values are, in practice, small values. Encoding such values using the number of bits equivalent to their maximum possible value is immensely wasteful. Consider using a `u32` to represent an index into an array, where all instances of that array are going to be smaller than 256 elements - encoding this value as a `u32` is going to waste 3 bytes for every index. Instead, using a variable-length encoding, the vast majority of indices will only require a single byte, with indices in the range 129-256 requiring a second byte. These savings add up considerably considering how frequently integer values are encoded.
* _Booleans are intrinsically-tagged_. In other words, the encoding of `true` and `false`, as `1` and `0` respectively, are also valid type tags for the boolean type. So storing a boolean requires only a single byte for both type tag and value, rather than a byte for each.
* _`Option<T>` is intrinsically tagged_. Similar to booleans, the value for `None` is just the type tag for `None`, while `Some` is encoded as the tag for `Some` followed by the encoded value of type `T`.

## Structure

The structure of a BITE-encoded stream is described using the Kaitai Struct language in [bite.ksy].
