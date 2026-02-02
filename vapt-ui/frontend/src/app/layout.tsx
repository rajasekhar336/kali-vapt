import './globals.css'
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'VAPT Security Dashboard | Enterprise Vulnerability Assessment',
  description: 'Production-grade Vulnerability Assessment and Penetration Testing platform with AI-powered remediation',
  keywords: ['VAPT', 'Security', 'Vulnerability Assessment', 'Penetration Testing', 'Cybersecurity'],
  authors: [{ name: 'VAPT Security Team' }],
  viewport: 'width=device-width, initial-scale=1',
  themeColor: '#2563eb',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <div id="root">
          {children}
        </div>
      </body>
    </html>
  )
}
