# !/bin/bash
#
# Script to to help render miden_vm generated constraints more readable.
# This is used to map the main trace to its layout, to index the trace more semantically.

# Note: as the current layout is misaligned (with unused columns), with the .air constraints (system has 8 columns instead of 6 in the .air layout),
# we apply a constant offset for all accesses to the main trace starting with fn_hash (index 4 in the .air).

# LAYOUT:
# ┌─────────┬──────────────────────────────────────────────────────────────────────┐
# │ Column  │                        Purpose                                       │
# ├─────────┼──────────────────────────────────────────────────────────────────────┤
# │    0    │ clk - VM execution clock (increments each cycle)                     │
# │    1    │ [UNUSED] Placeholder for trace layout compatibility                  │
# │    2    │ ctx - Current execution context                                      │
# │    3    │ [UNUSED] Placeholder for trace layout compatibility                  │
# │   4-7   │ fn_hash - Current function digest (4 elements)                       │
# │   8-31  │ decoder (24 elements)                                                │
# │  32-50  │ stack (19 elements)                                                  │
# │  51-52  │ range (2 elements)                                                   │
# │  53-72  │ chiplets (20 elements)                                               │
# └─────────┴──────────────────────────────────────────────────────────────────────┘

MISALIGNED_SYSTEMS_OFFSET=2

# List of files to update (hardcoded, based on current constraints folder)
FILES=(
  air/src/constraints/range/bus.rs
  air/src/constraints/range/mod.rs
  air/src/constraints/chiplets/ace/mod.rs
  air/src/constraints/chiplets/ace/bus.rs
  air/src/constraints/chiplets/periodic_columns.rs
  air/src/constraints/chiplets/memory/mod.rs
  air/src/constraints/chiplets/hasher/mod.rs
  air/src/constraints/chiplets/bus.rs
  air/src/constraints/chiplets/kernel_rom/mod.rs
  air/src/constraints/chiplets/bitwise/mod.rs
  air/src/constraints/chiplets/mod.rs
  air/src/constraints/mod.rs
  air/src/constraints/system.rs
  air/src/constraints/stack/bus.rs
  air/src/constraints/stack/mod.rs
  air/src/constraints/decoder/bus.rs
  air/src/constraints/decoder/mod.rs
)

# Update main trace accesses to use the new layout
# System
for f in "${FILES[@]}"; do
  sed -i \
    -e "s/main_current\[0\]\.clone()\.into()/local.clk.clone().into()/g" \
    -e "s/main_next\[0\]\.clone()\.into()/next.clk.clone().into()/g" \
    -e "s/main_current\[2\]\.clone()\.into()/local.ctx.clone().into()/g" \
    -e "s/main_next\[2\]\.clone()\.into()/next.ctx.clone().into()/g" \
    "$f"
done

# fn_hash[0..4]
for i in {0..3}; do
  idx=$((2 + i + MISALIGNED_SYSTEMS_OFFSET))
  for f in "${FILES[@]}"; do
    sed -i \
      -e "s/main_current\[$idx\]\.clone()\.into()/local.fn_hash[$i].clone().into()/g" \
      -e "s/main_next\[$idx\]\.clone()\.into()/next.fn_hash[$i].clone().into()/g" \
      "$f"
  done
done

# decoder[0..24] with offset
for i in {0..23}; do
  idx=$((6 + i + MISALIGNED_SYSTEMS_OFFSET))
  for f in "${FILES[@]}"; do
    sed -i \
      -e "s/main_current\[$idx\]\.clone()\.into()/local.decoder[$i].clone().into()/g" \
      -e "s/main_next\[$idx\]\.clone()\.into()/next.decoder[$i].clone().into()/g" \
      "$f"
  done
done

# stack[0..19] with offset
for i in {0..18}; do
  idx=$((30 + i + MISALIGNED_SYSTEMS_OFFSET))
  for f in "${FILES[@]}"; do
    sed -i \
      -e "s/main_current\[$idx\]\.clone()\.into()/local.stack[$i].clone().into()/g" \
      -e "s/main_next\[$idx\]\.clone()\.into()/next.stack[$i].clone().into()/g" \
      "$f"
  done
done

# range[0..2] with offset
for i in {0..1}; do
  idx=$((49 + i + MISALIGNED_SYSTEMS_OFFSET))
  for f in "${FILES[@]}"; do
    sed -i \
      -e "s/main_current\[$idx\]\.clone()\.into()/local.range[$i].clone().into()/g" \
      -e "s/main_next\[$idx\]\.clone()\.into()/next.range[$i].clone().into()/g" \
      "$f"
  done
done

# chiplets[0..20] with offset
for i in {0..19}; do
  idx=$((51 + i + MISALIGNED_SYSTEMS_OFFSET))
  for f in "${FILES[@]}"; do
    sed -i \
      -e "s/main_current\[$idx\]\.clone()\.into()/local.chiplets[$i].clone().into()/g" \
      -e "s/main_next\[$idx\]\.clone()\.into()/next.chiplets[$i].clone().into()/g" \
      "$f"
  done
done
