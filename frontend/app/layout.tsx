import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kaspersky Threat Intelligence Console",
  description: "Threat Intelligence and Security Center integration console",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
