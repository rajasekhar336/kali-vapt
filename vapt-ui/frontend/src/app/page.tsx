'use client'

import { useState } from 'react'
import ProductionDashboard from '@/components/ProductionDashboard'
import ScanWizard from '@/components/ScanWizard'
import VulnerabilityDetails from '@/components/VulnerabilityDetails'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Shield, Target, Activity, FileText, Settings, BarChart3, Users, Lock, Zap, TrendingUp, Download } from 'lucide-react'

type View = 'dashboard' | 'scan' | 'vulnerability' | 'reports' | 'settings'

export default function HomePage() {
  const [currentView, setCurrentView] = useState<View>('dashboard')
  const [selectedVulnerability, setSelectedVulnerability] = useState<any>(null)
  const [isScanning, setIsScanning] = useState(false)

  const handleStartScan = async (scanRequest: any) => {
    setIsScanning(true)
    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanRequest)
      })
      const result = await response.json()
      console.log('Scan started:', result)
      setCurrentView('dashboard')
    } catch (error) {
      console.error('Failed to start scan:', error)
    } finally {
      setIsScanning(false)
    }
  }

  const handleRequestRemediation = async (vulnId: string) => {
    try {
      const response = await fetch(`/api/vulnerabilities/${vulnId}/remediation`, {
        method: 'POST'
      })
      const result = await response.json()
      console.log('Remediation generated:', result)
    } catch (error) {
      console.error('Failed to get remediation:', error)
    }
  }

  const handleExportReport = async (vulnId: string) => {
    try {
      const response = await fetch(`/api/reports?vulnerability_id=${vulnId}&format=pdf`)
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `vulnerability-report-${vulnId}.pdf`
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export report:', error)
    }
  }

  const renderNavigation = () => (
    <nav className="bg-white border-b border-gray-200 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="text-xl font-bold text-gray-900">VAPT Platform</span>
            </div>
            <div className="hidden md:flex ml-10 space-x-8">
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                  currentView === 'dashboard'
                    ? 'text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <BarChart3 className="h-4 w-4 mr-2" />
                Dashboard
              </button>
              <button
                onClick={() => setCurrentView('scan')}
                className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                  currentView === 'scan'
                    ? 'text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <Target className="h-4 w-4 mr-2" />
                New Scan
              </button>
              <button
                onClick={() => setCurrentView('vulnerability')}
                className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                  currentView === 'vulnerability'
                    ? 'text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <Activity className="h-4 w-4 mr-2" />
                Vulnerabilities
              </button>
              <button
                onClick={() => setCurrentView('reports')}
                className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                  currentView === 'reports'
                    ? 'text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <FileText className="h-4 w-4 mr-2" />
                Reports
              </button>
              <button
                onClick={() => setCurrentView('settings')}
                className={`inline-flex items-center px-1 pt-1 text-sm font-medium ${
                  currentView === 'settings'
                    ? 'text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </button>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <Button variant="outline" size="sm">
              <Users className="h-4 w-4 mr-2" />
              Team
            </Button>
            <Button size="sm">
              <Zap className="h-4 w-4 mr-2" />
              Quick Scan
            </Button>
          </div>
        </div>
      </div>
    </nav>
  )

  const renderContent = () => {
    switch (currentView) {
      case 'dashboard':
        return (
          <ProductionDashboard
            onStartScan={() => setCurrentView('scan')}
            onRequestRemediation={handleRequestRemediation}
          />
        )
      case 'scan':
        return (
          <ScanWizard
            onStartScan={handleStartScan}
            isScanning={isScanning}
          />
        )
      case 'vulnerability':
        return (
          <div className="max-w-4xl mx-auto p-6">
            <Card>
              <CardHeader>
                <CardTitle>Select a Vulnerability</CardTitle>
                <CardDescription>
                  Choose a vulnerability from the dashboard to view detailed information
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Button onClick={() => setCurrentView('dashboard')}>
                  Back to Dashboard
                </Button>
              </CardContent>
            </Card>
          </div>
        )
      case 'reports':
        return (
          <div className="max-w-6xl mx-auto p-6">
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
                <FileText className="h-8 w-8 text-blue-600" />
                Security Reports
              </h1>
              <p className="text-gray-600 mt-2">Generate and download comprehensive security assessment reports</p>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <Card className="hover:shadow-xl transition-shadow duration-200">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Executive Summary
                  </CardTitle>
                  <CardDescription>High-level overview for stakeholders</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button className="w-full">
                    <Download className="h-4 w-4 mr-2" />
                    Generate PDF
                  </Button>
                </CardContent>
              </Card>
              
              <Card className="hover:shadow-xl transition-shadow duration-200">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Technical Report
                  </CardTitle>
                  <CardDescription>Detailed findings for technical teams</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button className="w-full" variant="outline">
                    <Download className="h-4 w-4 mr-2" />
                    Generate Word
                  </Button>
                </CardContent>
              </Card>
              
              <Card className="hover:shadow-xl transition-shadow duration-200">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <TrendingUp className="h-5 w-5" />
                    Compliance Report
                  </CardTitle>
                  <CardDescription>Regulatory compliance assessment</CardDescription>
                </CardHeader>
                <CardContent>
                  <Button className="w-full" variant="outline">
                    <Download className="h-4 w-4 mr-2" />
                    Generate Excel
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        )
      case 'settings':
        return (
          <div className="max-w-4xl mx-auto p-6">
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
                <Settings className="h-8 w-8 text-blue-600" />
                Platform Settings
              </h1>
              <p className="text-gray-600 mt-2">Configure your VAPT platform preferences</p>
            </div>
            
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Scan Configuration</CardTitle>
                  <CardDescription>Default settings for vulnerability scans</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium">Auto-start remediation</h4>
                        <p className="text-sm text-gray-600">Automatically generate AI remediation for new vulnerabilities</p>
                      </div>
                      <Button variant="outline" size="sm">Configure</Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        )
      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {renderNavigation()}
      <main>
        {renderContent()}
      </main>
    </div>
  )
}
