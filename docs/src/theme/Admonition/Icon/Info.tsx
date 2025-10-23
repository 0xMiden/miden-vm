import React, { type ReactNode } from "react";
import type { Props } from "@theme/Admonition/Icon/Info";

export default function AdmonitionIconInfo(props: Props): ReactNode {
  return (
    <svg
      width="13"
      height="17"
      viewBox="0 0 13 17"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      <path
        d="M3.33332 0.583313H9.66666V2.16665H3.33332V0.583313ZM1.74999 3.74998V2.16665H3.33332V3.74998H1.74999ZM1.74999 8.49998H0.166656V3.74998H1.74999V8.49998ZM3.33332 10.0833H1.74999V8.49998H3.33332V10.0833ZM9.66666 10.0833V13.25H3.33332V10.0833H4.91666V11.6666H8.08332V10.0833H9.66666ZM11.25 8.49998V10.0833H9.66666V8.49998H11.25ZM11.25 3.74998H12.8333V8.49998H11.25V3.74998ZM11.25 3.74998V2.16665H9.66666V3.74998H11.25ZM9.66666 14.8333H3.33332V16.4166H9.66666V14.8333Z"
        fill="#102445"
      />
    </svg>
  );
}
