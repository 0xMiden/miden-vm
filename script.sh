for i in {53..73}; do
  j=$((i-53))
  sed -i \
    -e "s/main_current\[$i\]\.clone()\.\into()/local.chiplets[$j].clone().into()/g" \
    -e "s/main_next\[$i\]\.clone()\.\into()/next.chiplets[$j].clone().into()/g" \
    air/src/constraints/chiplets/ace/mod.rs
  sed -i \
    -e "s/main_current\[$i\]\.clone()\.\into()/local.chiplets[$j].clone().into()/g" \
    -e "s/main_next\[$i\]\.clone()\.\into()/next.chiplets[$j].clone().into()/g" \
    air/src/constraints/chiplets/bitwise/mod.rs
  sed -i \
    -e "s/main_current\[$i\]\.clone()\.\into()/local.chiplets[$j].clone().into()/g" \
    -e "s/main_next\[$i\]\.clone()\.\into()/next.chiplets[$j].clone().into()/g" \
    air/src/constraints/chiplets/hasher/mod.rs
  sed -i \
    -e "s/main_current\[$i\]\.clone()\.\into()/local.chiplets[$j].clone().into()/g" \
    -e "s/main_next\[$i\]\.clone()\.\into()/next.chiplets[$j].clone().into()/g" \
    air/src/constraints/chiplets/kernel_rom/mod.rs
  sed -i \
    -e "s/main_current\[$i\]\.clone()\.\into()/local.chiplets[$j].clone().into()/g" \
    -e "s/main_next\[$i\]\.clone()\.\into()/next.chiplets[$j].clone().into()/g" \
    air/src/constraints/chiplets/memory/mod.rs
done
