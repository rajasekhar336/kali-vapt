'use client'

import * as React from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Shield, AlertTriangle, CheckCircle, Clock, Target, Zap, TrendingUp, Activity } from 'lucide-react'

interface Vulnerability {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tool: string
  endpoint: string
  status: 'open' | 'in_progress' | 'resolved'
  cvss_score?: number
  discovered_at: string
  has_remediation?: boolean
}

interface Scan {
  id: string
  target_domain: string
  scan_type: string
  status: 'running' | 'completed' | 'failed' | 'pending'
  started_at: string
  completed_at?: string
  vulnerabilities_count: number
  progress?: number
}

interface DashboardStats {
  total_scans: number
  active_scans: number
  total_vulnerabilities: number
  critical_vulnerabilities: number
  remediation_rate: number
}

interface ProductionDashboardProps {
  stats?: DashboardStats
  recentScans?: Scan[]
  recentVulnerabilities?: Vulnerability[]
  onStartScan?: (domain: string) => void
  onRequestRemediation?: (vulnId: string) => void
}

export default function ProductionDashboard({
  stats = {
    total_scans: 156,
    active_scans: 3,
    total_vulnerabilities: 1247,
    critical_vulnerabilities: 23,
    remediation_rate: 78.5
  },
  recentScans = [
    {
      id: 'scan-001',
      target_domain: 'example.com',
      scan_type: 'Full Assessment',
      status: 'running',
      started_at: '2026-02-02T00:30:00Z',
      vulnerabilities_count: 0,
      progress: 67
    },
    {
      id: 'scan-002', 
      target_domain: 'test-site.org',
      scan_type: 'Quick Scan',
      status: 'completed',
      started_at: '2026-02-01T23:45:00Z',
      completed_at: '2026-02-02T00:15:00Z',
      vulnerabilities_count: 12
    }
  ],
  recentVulnerabilities = [
    {
      id: 'vuln-001',
      title: 'SQL Injection in Login Form',
      severity: 'critical',
      tool: 'SQLMap',
      endpoint: '/login',
      status: 'open',
      cvss_score: 9.8,
      discovered_at: '2026-02-02T00:15:00Z',
      has_remediation: false
    },
    {
      id: 'vuln-002',
      title: 'Missing Security Headers',
      severity: 'medium',
      tool: 'Nuclei',
      endpoint: '/',
      status: 'in_progress',
      cvss_score: 5.4,
      discovered_at: '2026-02-02T00:10:00Z',
      has_remediation: true
    }
  ],
  onStartScan,
  onRequestRemediation
}: ProductionDashboardProps) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'warning'
      case 'low': return 'secondary'
      default: return 'outline'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'info'
      case 'completed': return 'success'
      case 'failed': return 'destructive'
      default: return 'secondary'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <Clock className="h-4 w-4" />
      case 'completed': return <CheckCircle className="h-4 w-4" />
      case 'failed': return <AlertTriangle className="h-4 w-4" />
      default: return <Clock className="h-4 w-4" />
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-slate-900 flex items-center gap-3">
              <Shield className="h-10 w-10 text-blue-600" />
              VAPT Security Dashboard
            </h1>
            <p className="text-slate-600 mt-2">Enterprise Vulnerability Assessment & Penetration Testing</p>
          </div>
          <Button size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700">
            <Zap className="h-5 w-5 mr-2" />
            Start New Scan
          </Button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        <Card className="hover:shadow-xl transition-shadow duration-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-600">Total Scans</p>
                <p className="text-3xl font-bold text-slate-900">{stats.total_scans}</p>
              </div>
              <Target className="h-8 w-8 text-blue-600" />
            </div>
            <div className="mt-4 flex items-center text-sm">
              <TrendingUp className="h-4 w-4 text-green-600 mr-1" />
              <span className="text-green-600">+12%</span>
              <span className="text-slate-600 ml-1">from last month</span>
            </div>
          </CardContent>
        </Card>

        <Card className="hover:shadow-xl transition-shadow duration-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-600">Active Scans</p>
                <p className="text-3xl font-bold text-slate-900">{stats.active_scans}</p>
              </div>
              <Activity className="h-8 w-8 text-green-600" />
            </div>
            <div className="mt-4">
              <Progress value={stats.active_scans * 33} className="h-2" />
            </div>
          </CardContent>
        </Card>

        <Card className="hover:shadow-xl transition-shadow duration-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-600">Total Vulnerabilities</p>
                <p className="text-3xl font-bold text-slate-900">{stats.total_vulnerabilities}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-yellow-600" />
            </div>
            <div className="mt-4 flex items-center text-sm">
              <AlertTriangle className="h-4 w-4 text-yellow-600 mr-1" />
              <span className="text-yellow-600">{stats.critical_vulnerabilities} critical</span>
            </div>
          </CardContent>
        </Card>

        <Card className="hover:shadow-xl transition-shadow duration-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-600">Critical Issues</p>
                <p className="text-3xl font-bold text-red-600">{stats.critical_vulnerabilities}</p>
              </div>
              <Shield className="h-8 w-8 text-red-600" />
            </div>
            <div className="mt-4">
              <Badge variant="destructive" className="text-xs">
                Immediate Action Required
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card className="hover:shadow-xl transition-shadow duration-200">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-600">Remediation Rate</p>
                <p className="text-3xl font-bold text-green-600">{stats.remediation_rate}%</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-600" />
            </div>
            <div className="mt-4">
              <Progress value={stats.remediation_rate} className="h-2" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5" />
              Recent Scans
            </CardTitle>
            <CardDescription>Latest security assessment runs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentScans.map((scan) => (
                <div key={scan.id} className="flex items-center justify-between p-4 rounded-lg border bg-slate-50 hover:bg-slate-100 transition-colors">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-medium text-slate-900">{scan.target_domain}</h4>
                      <Badge variant={getStatusColor(scan.status)} className="text-xs">
                        {getStatusIcon(scan.status)}
                        <span className="ml-1">{scan.status.replace('_', ' ')}</span>
                      </Badge>
                    </div>
                    <p className="text-sm text-slate-600">{scan.scan_type}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                      <span>Started: {new Date(scan.started_at).toLocaleTimeString()}</span>
                      {scan.vulnerabilities_count > 0 && (
                        <span className="text-yellow-600 font-medium">
                          {scan.vulnerabilities_count} vulnerabilities found
                        </span>
                      )}
                    </div>
                    {scan.progress && (
                      <div className="mt-2">
                        <Progress value={scan.progress} className="h-1" />
                        <span className="text-xs text-slate-500 mt-1">{scan.progress}% complete</span>
                      </div>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <Button size="sm" variant="outline">
                      View Details
                    </Button>
                    {scan.status === 'completed' && (
                      <Button size="sm">
                        Download Report
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Critical Vulnerabilities */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              Critical Vulnerabilities
            </CardTitle>
            <CardDescription>High-priority security issues requiring immediate attention</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentVulnerabilities.map((vuln) => (
                <div key={vuln.id} className="flex items-center justify-between p-4 rounded-lg border bg-red-50 hover:bg-red-100 transition-colors">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-medium text-slate-900">{vuln.title}</h4>
                      <Badge variant={getSeverityColor(vuln.severity)} className="text-xs">
                        {vuln.severity.toUpperCase()}
                      </Badge>
                      {vuln.cvss_score && (
                        <Badge variant="outline" className="text-xs">
                          CVSS: {vuln.cvss_score}
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-slate-600">
                      <span className="font-medium">Tool:</span> {vuln.tool} • 
                      <span className="font-medium ml-2">Endpoint:</span> {vuln.endpoint}
                    </p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                      <span>Discovered: {new Date(vuln.discovered_at).toLocaleTimeString()}</span>
                      <Badge variant={vuln.has_remediation ? 'success' : 'secondary'} className="text-xs">
                        {vuln.has_remediation ? 'Remediation Available' : 'No Remediation'}
                      </Badge>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {!vuln.has_remediation && (
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => onRequestRemediation?.(vuln.id)}
                      >
                        Get AI Remediation
                      </Button>
                    )}
                    {vuln.has_remediation && (
                      <Button size="sm">
                        View Remediation
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
