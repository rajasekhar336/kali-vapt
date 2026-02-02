'use client'

import { useState, useEffect } from 'react'
import ProductionDashboard from '@/components/ProductionDashboard'
import ScanWizard from '@/components/ScanWizard'
import VulnerabilityDetails from '@/components/VulnerabilityDetails'
import ScanDetails from '@/components/ScanDetails'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ThemeToggle } from '@/components/theme-toggle'
import { Shield, Target, Activity, FileText, Settings, BarChart3, Users, Lock, Zap, TrendingUp, Download, Sparkles, ChevronRight } from 'lucide-react'

type View = 'dashboard' | 'scan' | 'vulnerability' | 'reports' | 'settings' | 'scan_details'

export default function HomePage() {
  const [currentView, setCurrentView] = useState<View>('dashboard')
  const [selectedVulnerability, setSelectedVulnerability] = useState<any>(null)
  const [selectedScan, setSelectedScan] = useState<any>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [stats, setStats] = useState<any>(null)
  const [recentScans, setRecentScans] = useState<any[]>([])
  const [recentVulnerabilities, setRecentVulnerabilities] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchDashboardData()
  }, [])

  const fetchDashboardData = async () => {
    setLoading(true)
    try {
      const [statsRes, scansRes, vulnsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/scans?limit=5'),
        fetch('/api/vulnerabilities?limit=5')
      ])

      const [statsData, scansData, vulnsData] = await Promise.all([
        statsRes.json(),
        scansRes.json(),
        vulnsRes.json()
      ])

      setStats(statsData)
      setRecentScans(scansData.scans || [])
      setRecentVulnerabilities(vulnsData.vulnerabilities || [])
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

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
      fetchDashboardData()
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
    <nav className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 shadow-lg sticky top-0 z-50 transition-colors duration-300">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400 float-animation" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-500 rounded-full pulse-glow"></div>
              </div>
              <span className="text-xl font-bold text-gray-900 dark:text-white gradient-text dark:gradient-text-dark">VAPT Platform</span>
            </div>
            <div className="hidden md:flex ml-10 space-x-8">
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${currentView === 'dashboard'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
              >
                <BarChart3 className="h-4 w-4 mr-2" />
                Dashboard
              </button>
              <button
                onClick={() => setCurrentView('scan')}
                className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${currentView === 'scan'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
              >
                <Target className="h-4 w-4 mr-2" />
                New Scan
              </button>
              <button
                onClick={() => setCurrentView('vulnerability')}
                className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${currentView === 'vulnerability'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
              >
                <Activity className="h-4 w-4 mr-2" />
                Vulnerabilities
              </button>
              <button
                onClick={() => setCurrentView('reports')}
                className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${currentView === 'reports'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
              >
                <FileText className="h-4 w-4 mr-2" />
                Reports
              </button>
              <button
                onClick={() => setCurrentView('settings')}
                className={`inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-all duration-200 ${currentView === 'settings'
                  ? 'bg-blue-600 text-white shadow-lg'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                  }`}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </button>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <ThemeToggle />
            <Button variant="outline" size="sm" className="border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
              <Users className="h-4 w-4 mr-2" />
              Team
            </Button>
            <Button size="sm" className="btn-gradient">
              <Sparkles className="h-4 w-4 mr-2" />
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
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
            <ProductionDashboard
              stats={stats}
              recentScans={recentScans}
              recentVulnerabilities={recentVulnerabilities}
              onStartScan={() => setCurrentView('scan')}
              onRequestRemediation={handleRequestRemediation}
              onSelectVulnerability={(vuln) => {
                setSelectedVulnerability(vuln)
                setCurrentView('vulnerability')
              }}
              onSelectScan={(scan) => {
                setSelectedScan(scan)
                setCurrentView('scan_details')
              }}
            />
          </div>
        )
      case 'scan':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
            <ScanWizard
              onStartScan={handleStartScan}
              isScanning={isScanning}
            />
          </div>
        )
      case 'scan_details':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
            {selectedScan && (
              <ScanDetails
                scan={selectedScan}
                onBack={() => setCurrentView('dashboard')}
                onSelectVulnerability={(vuln) => {
                  setSelectedVulnerability(vuln)
                  setCurrentView('vulnerability')
                }}
              />
            )}
          </div>
        )
      case 'vulnerability':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
            {selectedVulnerability ? (
              <VulnerabilityDetails
                vulnerability={selectedVulnerability}
                onRequestRemediation={handleRequestRemediation}
                onExportReport={handleExportReport}
              />
            ) : (
              <Card className="max-w-4xl mx-auto bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 shadow-lg hover:shadow-xl transition-all duration-300 fade-in">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                    Select a Vulnerability
                  </CardTitle>
                  <CardDescription className="text-gray-600 dark:text-gray-300">
                    Choose a vulnerability from the dashboard to view detailed information
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Button onClick={() => setCurrentView('dashboard')} className="btn-gradient">
                    Back to Dashboard
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>
        )
      case 'reports':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
            <div className="max-w-6xl mx-auto fade-in">
              <div className="mb-8 text-center">
                <h1 className="text-4xl font-bold text-gray-900 dark:text-white flex items-center justify-center gap-3 mb-4">
                  <FileText className="h-10 w-10 text-blue-600 dark:text-blue-400" />
                  Security Reports
                </h1>
                <p className="text-gray-600 dark:text-gray-300 text-lg">Generate and download comprehensive security assessment reports</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <Card className="bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-white">
                      <FileText className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                      Executive Summary
                    </CardTitle>
                    <CardDescription className="text-gray-600 dark:text-gray-300">High-level overview for stakeholders</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button className="w-full btn-gradient">
                      <Download className="h-4 w-4 mr-2" />
                      Generate PDF
                    </Button>
                  </CardContent>
                </Card>

                <Card className="bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-white">
                      <Lock className="h-5 w-5 text-green-600 dark:text-green-400" />
                      Technical Report
                    </CardTitle>
                    <CardDescription className="text-gray-600 dark:text-gray-300">Detailed findings for technical teams</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button className="w-full bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors duration-200">
                      <Download className="h-4 w-4 mr-2" />
                      Generate Word
                    </Button>
                  </CardContent>
                </Card>

                <Card className="bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-gray-900 dark:text-white">
                      <TrendingUp className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                      Compliance Report
                    </CardTitle>
                    <CardDescription className="text-gray-600 dark:text-gray-300">Regulatory compliance assessment</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Button className="w-full bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors duration-200">
                      <Download className="h-4 w-4 mr-2" />
                      Generate Excel
                    </Button>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        )
      case 'settings':
        return (
          <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
            <div className="max-w-4xl mx-auto fade-in">
              <div className="mb-8 text-center">
                <h1 className="text-4xl font-bold text-gray-900 dark:text-white flex items-center justify-center gap-3 mb-4">
                  <Settings className="h-10 w-10 text-blue-600 dark:text-blue-400" />
                  Platform Settings
                </h1>
                <p className="text-gray-600 dark:text-gray-300 text-lg">Configure your VAPT platform preferences</p>
              </div>

              <div className="space-y-6">
                <Card className="bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 shadow-lg hover:shadow-xl transition-all duration-300">
                  <CardHeader>
                    <CardTitle className="text-gray-900 dark:text-white">Scan Configuration</CardTitle>
                    <CardDescription className="text-gray-600 dark:text-gray-300">Default settings for vulnerability scans</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium text-gray-900 dark:text-white">Auto-start remediation</h4>
                          <p className="text-sm text-gray-600 dark:text-gray-300">Automatically generate AI remediation for new vulnerabilities</p>
                        </div>
                        <Button variant="outline" size="sm" className="border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-200">
                          Configure
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </div>
        )
      default:
        return null
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-300">
      {renderNavigation()}
      <main className="transition-colors duration-300">
        {renderContent()}
      </main>
    </div>
  )
}
