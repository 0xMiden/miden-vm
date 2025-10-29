import React, { type ReactNode } from "react";
import type { Props } from "@theme/Admonition/Icon/Note";

export default function AdmonitionIconNote(props: Props): ReactNode {
  return (
    <svg
      width="15"
      height="17"
      viewBox="0 0 15 17"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      <path
        d="M0.375 0.583313H14.625V11.6666H13.0417V13.25H11.4583V11.6666H9.875V13.25H11.4583V14.8333H9.875V16.4166H0.375V0.583313ZM1.95833 2.16665V14.8333H8.29167V10.0833H13.0417V2.16665H1.95833Z"
        fill="#df9f26"
      />
    </svg>
  );
}
