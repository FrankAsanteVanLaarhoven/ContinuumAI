import "./globals.css";
import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Continuum · Sovereign Intent & Agency Infrastructure",
  description:
    "Owner-controlled identity, intent, memory, authorization, and provenance control plane governing how heterogeneous agents obtain context and exercise agency.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
