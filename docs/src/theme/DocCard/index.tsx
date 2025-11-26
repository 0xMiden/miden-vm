import React, { type ReactNode } from "react";
import DocCard from "@theme-original/DocCard";
import type DocCardType from "@theme/DocCard";
import type { WrapperProps } from "@docusaurus/types";
import styles from "./styles.module.css";

type Props = WrapperProps<typeof DocCardType>;

export default function DocCardWrapper(props: Props): ReactNode {
  return (
    <div className={styles.customCard}>
      <DocCard {...props} />
    </div>
  );
}
