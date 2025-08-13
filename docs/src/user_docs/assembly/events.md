## Events

Miden assembly supports a comprehensive event system for communication between programs and the host environment. Events allow programs to signal specific occurrences or provide contextual information to the host, which can then take appropriate actions. The emission of events does not change the state of the VM but can trigger changes in the host environment.

### Event System Overview

The Miden VM event system supports two types of event identification:

1. **Legacy u32 Events**: Simple 32-bit numeric identifiers (backward compatible)
2. **Enhanced EventId System**: Hierarchical string-based identifiers with cryptographic hashing

### Legacy Events

Legacy events use simple 32-bit identifiers and can be emitted directly:

```
emit.EVENT_ID_1  # Using named constant
emit.2          # Direct numeric value
```

### Enhanced EventId System

The enhanced event system uses hierarchical string-based identifiers with the format:

```
<source>/<namespace>::<EVENT_NAME>
```

Where:
- `<source>`: Event source (e.g., `miden-vm`, `miden-stdlib`, `lib-0`, `user-0`)
- `<namespace>`: Logical grouping within the source (e.g., `crypto`, `math`)  
- `<EVENT_NAME>`: Specific event name (uppercase with underscores)

#### Event Sources

The system supports different event sources for organizing events hierarchically:

- **`miden-vm/*`**: Built-in VM system events  
- **`miden-stdlib/*`**: Standard library events
- **`lib-N/*`**: Third-party library events (N = library ID)
- **`user-N/*`**: User-defined application events (N = user ID)

#### Example EventIds

```
miden-vm/system::HALT_REQUESTED
miden-stdlib/crypto::HASH_COLLISION_DETECTED  
user-0/trading::ORDER_EXECUTED
lib-5/oracle::PRICE_UPDATED
```

#### Blake3 Hashing and Collision Detection

EventIds are converted to Felt values using Blake3 cryptographic hashing with domain separation:

1. **Domain Construction**: `miden-event:<source>/<namespace>`
2. **Input Construction**: `<EVENT_NAME>`
3. **Blake3 Hash**: Computed over domain + input
4. **Felt Conversion**: Hash truncated/reduced to valid Felt value

The system automatically detects hash collisions and provides resolution strategies:

- **Error**: Reject colliding events (default)
- **Rename**: Automatically rename one of the colliding events
- **Manual**: Use explicit Felt mapping to resolve collision

#### Reverse Lookup

The enhanced system maintains bidirectional mapping between EventIds and Felt values, enabling:

- **Forward Lookup**: EventId → Felt (for emission)
- **Reverse Lookup**: Felt → EventId (for debugging and host handling)

This allows the host to resolve Felt event values back to meaningful EventId names for enhanced debugging and logging.

### Emitting Events

Events are emitted using the `emit.<event_id>` instruction:

```assembly
# Legacy numeric events
emit.42
emit.EVENT_CONSTANT

# Enhanced EventId events (when supported by assembler)
emit."user-0/trading::ORDER_EXECUTED"
emit."miden-stdlib/crypto::SIGNATURE_VERIFIED"
```

**Note**: The exact syntax for enhanced EventId emission may vary depending on assembler implementation.

### Event Management CLI

The Miden VM provides comprehensive CLI tools for managing and analyzing events in programs:

#### List Events
```bash
# List all events in a program
miden-vm events list -a program.masm

# List events with library dependencies
miden-vm events list -a program.masm -l lib1.masl -l lib2.masl

# Filter by event source
miden-vm events list -a program.masm --source-filter user

# Show Felt values alongside event names
miden-vm events list -a program.masm --show-felt

# Output in different formats
miden-vm events list -a program.masm --format json
miden-vm events list -a program.masm --format csv
```

#### Validate Events
```bash
# Validate event naming and check for collisions
miden-vm events validate -a program.masm

# Include collision detection
miden-vm events validate -a program.masm --check-collisions

# Strict mode (fail on warnings)
miden-vm events validate -a program.masm --strict
```

#### Event Information
```bash
# Get detailed info about a specific event
miden-vm events info -a program.masm "user-0/trading::ORDER_EXECUTED"

# Reverse lookup: get EventId from Felt value
miden-vm events info -a program.masm 12345678901234567890
```

#### Generate Documentation
```bash
# Generate Markdown documentation
miden-vm events docs -a program.masm -f markdown -o events.md

# Generate HTML documentation
miden-vm events docs -a program.masm -f html -o events.html

# Generate JSON documentation
miden-vm events docs -a program.masm -f json -o events.json
```

### Best Practices

1. **Naming Conventions**:
   - Use uppercase with underscores for event names: `ORDER_EXECUTED`
   - Use lowercase for namespaces: `trading`, `crypto`
   - Keep names descriptive but concise

2. **Organization**:
   - Group related events under common namespaces
   - Use hierarchical sources appropriately
   - Avoid overly deep nesting

3. **Collision Avoidance**:
   - Use the validation tools regularly
   - Choose distinctive event names
   - Consider domain-specific prefixes for clarity

4. **Documentation**:
   - Use the documentation generation tools
   - Include event descriptions in your code comments
   - Keep event documentation up to date

## Tracing

Miden assembly also supports code tracing, which works similar to the event emitting. 

A trace can be emitted via the `trace.<trace_id>` assembly instruction where `<trace_id>` can be any 32-bit value specified either directly or via a [named constant](./code_organization.md#constants). For example:

```
trace.EVENT_ID_1
trace.2
```

To make use of the `trace` instruction, programs should be ran with tracing flag (`-t` or `--trace`), otherwise these instructions will be ignored.
