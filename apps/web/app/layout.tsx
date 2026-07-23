import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MandateMesh — Mandate-Enforced Agent Payments",
  description: "Run an accounts-payable agent unprotected, then behind a signed-mandate policy gateway.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

