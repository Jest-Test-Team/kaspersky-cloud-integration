import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kaspersky Threat Intelligence Console",
  description: "Official Kaspersky cloud Threat Intelligence API console",
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
