# Enhanced Event System Examples

This directory contains examples demonstrating the Miden VM's enhanced event system capabilities.

## Examples

### `enhanced_events_demo.masm`

Demonstrates both legacy numeric events and the enhanced EventId system concepts:

- **Legacy Events**: Backward-compatible 32-bit numeric events
- **Enhanced EventIds**: Hierarchical string-based event identifiers (conceptual syntax)
- **Event Sources**: System, user, library, and standard library events
- **Naming Conventions**: Proper hierarchical organization

### Running the Examples

```bash
# Compile and run the enhanced events demo
miden-vm run -a enhanced_events_demo.masm

# Analyze events in the program
miden-vm events list -a enhanced_events_demo.masm

# Validate events for collisions and naming
miden-vm events validate -a enhanced_events_demo.masm

# Generate event documentation
miden-vm events docs -a enhanced_events_demo.masm -f markdown
```

## Event System Features

The enhanced event system provides:

1. **Hierarchical Organization**: Events organized by source and namespace
2. **Collision Detection**: Automatic detection of hash collisions between EventIds  
3. **Reverse Lookup**: Bidirectional mapping between EventIds and Felt values
4. **CLI Tooling**: Comprehensive command-line tools for event management
5. **Backward Compatibility**: Full support for legacy numeric events

## EventId Format

```
<source>/<namespace>::<EVENT_NAME>
```

**Examples:**
- `miden-vm/system::HALT_REQUESTED`
- `miden-stdlib/crypto::SIGNATURE_VERIFIED`
- `user-0/trading::ORDER_EXECUTED`
- `lib-5/oracle::PRICE_UPDATED`

## Best Practices

1. **Use descriptive names**: `ORDER_EXECUTED` vs `EVENT_42`
2. **Organize by namespace**: Group related events together
3. **Follow naming conventions**: Uppercase events, lowercase namespaces
4. **Validate regularly**: Use CLI tools to check for collisions
5. **Document events**: Generate and maintain event documentation

See the [Events Documentation](../../docs/src/user_docs/assembly/events.md) for complete details.