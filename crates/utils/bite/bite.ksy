meta:
  id: bite
  title: BITE-encoded file
  file-extension: bite
  endian: le
  bit-endian: le
seq:
  - id: magic
    contents: 'BITE\0'
  - id: version
    type: u8
  - id: strings
    type: string_table
  - id: payload
    type: payload
    repeat: eos
enum:
  tag:
    false: 0
    true: 1
    none: 2
    some: 3
    int: 4
    sint: 5
    i8: 6
    u8: 7
    f32: 8
    f64: 9
    char: 10
    bytes: 11
    str: 12
    seq: 13
    map: 14
    unit_variant: 15
    newtype_variant: 16
    struct_variant: 17
    tuple_variant: 18
types:
  unit:
    seq:
      - id: empty
        size: 0
  payload:
    doc: An encoded value tagged with its serde data type
    seq:
      - id: tag
        type: u8
        enum: tag
      - id: value
        type:
          switch-on: tag
          cases:
            'tag::false': unit
            'tag::true': unit
            'tag::none': unit
            'tag::some': payload
            'tag::int': varint
            'tag::sint': varint
            'tag::i8': u8
            'tag::u8': u8
            'tag::f32': f32
            'tag::f64': f64
            'tag::char': varint
            'tag::bytes': payload_bytes
            'tag::str': varint
            'tag::seq': payload_seq
            'tag::map': payload_map
            'tag::unit_variant': unit
            'tag::newtype_variant': payload
            'tag::struct_variant': payload_variant
            'tag::tuple_variant': payload_variant
  payload_variant:
    doc: A hint to the deserializer that a given enum variant is next in the stream
    seq:
      - id: variant_id
        type: varint
  payload_seq:
    seq:
      - id: num_elements
        type: varint
      - id: num_element_bytes
        type: varint
        if: num_elements.value > 0
        doc: The number of subsequent bytes holding the encoded elements of this sequence
      - id: elements
        type: payload
        if: num_elements.value > 0
        size: num_element_bytes.value
        repeat: expr
        repeat-expr: num_elements.value
  payload_map:
    seq:
      - id: num_elements
        type: varint
      - id: num_key_bytes
        type: varint
        if: num_elements.value > 0
        doc: The number of subsequent bytes holding the encoded keys of this map
      - id: keys
        type: payload
        if: num_elements.value > 0
        size: num_key_bytes.value
        repeat: expr
        repeat-expr: num_elements.value
      - id: num_value_bytes
        type: varint
        if: num_elements.value > 0
        doc: The number of subsequent bytes holding the encoded values of this map
      - id: values
        type: payload
        if: num_elements.value > 0
        size: num_value_bytes.value
        repeat: expr
        repeat-expr: num_elements.value
  payload_bytes:
    seq:
      - id: num_bytes
        type: varint
      - id: bytes
        size: num_bytes.value
  strings_table:
    doc: The interned strings table
    seq:
      - id: num_strings
        type: varint
      - id: string_entries
        type: string_entry
        repeat: expr
        repeat-expr: num_strings.value
  string_entry:
    doc: An entry in the interned string table
    seq:
      - id: string_len
        type: varint
      - id: string_data
        type: str
        size: string_len.value
        encoding: UTF-8
  varint:
    doc: A variable-length encoded integer value
    seq:
      - id: varint_groups
        type: varint_group
        repeat: until
        repeat-until: not _.has_next
    instances:
      last:
        value: varint_groups.size - 1
      value:
        value: >-
          groups[last].value
          + (last >= 1 ? (varint_groups[last - 1].value << 7) : 0)
          + (last >= 2 ? (varint_groups[last - 2].value << 14) : 0)
          + (last >= 3 ? (varint_groups[last - 3].value << 21) : 0)
          + (last >= 4 ? (varint_groups[last - 4].value << 28) : 0)
          + (last >= 5 ? (varint_groups[last - 5].value << 35) : 0)
          + (last >= 6 ? (varint_groups[last - 6].value << 42) : 0)
          + (last >= 7 ? (varint_groups[last - 7].value << 49) : 0)
        doc: Resulting value as normal integer
  varint_group:
    seq:
      - id: b
        type: u1
    instances:
      has_next:
        value: (b & 0b1000_0000) != 0
        doc: If true, then we have more bytes to read
      value:
        value: b & 0b0111_1111
        doc: The 7-bit (base128) numeric value chunk of this group
