import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MandateMesh — Unprotected Attack Baseline",
  description: "Inspect an accounts-payable agent crossing the action boundary.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

