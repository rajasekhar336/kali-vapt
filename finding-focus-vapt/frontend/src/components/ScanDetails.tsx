'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import {
    Shield,
    Activity,
    Target,
    Calendar,
    Clock,
    CheckCircle2,
    AlertTriangle,
    ArrowLeft,
    Loader2,
    ExternalLink,
    ChevronRight
} from 'lucide-react'

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

interface Vulnerability {
    id: string
    title: string
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
    tool_name: string
    endpoint: string
    description: string
    cvss_score?: number
    created_at: string
}

interface ScanDetailsProps {
    scan: Scan
    onBack: () => void
    onSelectVulnerability: (vuln: Vulnerability) => void
}

export default function ScanDetails({ scan, onBack, onSelectVulnerability }: ScanDetailsProps) {
    const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchVulnerabilities()
    }, [scan.id])

    const fetchVulnerabilities = async () => {
        setLoading(true)
        try {
            const response = await fetch(`/api/scans/${scan.id}/vulnerabilities`)
            const data = await response.json()
            setVulnerabilities(data.vulnerabilities || [])
        } catch (error) {
            console.error('Failed to fetch vulnerabilities:', error)
        } finally {
            setLoading(false)
        }
    }

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'completed': return 'success'
            case 'running': return 'default'
            case 'failed': return 'destructive'
            default: return 'secondary'
        }
    }

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'critical': return 'destructive'
            case 'high': return 'destructive'
            case 'medium': return 'warning'
            case 'low': return 'secondary'
            default: return 'outline'
        }
    }

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-6 animate-in fade-in duration-500">
            <div className="flex items-center justify-between">
                <Button variant="ghost" onClick={onBack} className="flex items-center gap-2 hover:bg-white dark:hover:bg-gray-800">
                    <ArrowLeft className="h-4 w-4" />
                    Back to Dashboard
                </Button>
                <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={fetchVulnerabilities}>
                        Refresh Results
                    </Button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-1 space-y-6">
                    <Card className="border-blue-100 dark:border-blue-900 shadow-sm">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2 text-xl">
                                <Target className="h-5 w-5 text-blue-600" />
                                Scan Information
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div>
                                <p className="text-sm text-slate-500 mb-1">Target Domain</p>
                                <p className="font-semibold text-lg flex items-center gap-2">
                                    {scan.target_domain}
                                    <ExternalLink className="h-4 w-4 text-slate-400" />
                                </p>
                            </div>
                            <div>
                                <p className="text-sm text-slate-500 mb-1">Status</p>
                                <Badge variant={getStatusColor(scan.status)}>
                                    {scan.status.toUpperCase()}
                                </Badge>
                            </div>
                            <div>
                                <p className="text-sm text-slate-500 mb-1">Scan Type</p>
                                <p className="font-medium">{scan.scan_type}</p>
                            </div>
                            <div>
                                <p className="text-sm text-slate-500 mb-1">Started At</p>
                                <p className="flex items-center gap-2 text-sm">
                                    <Calendar className="h-4 w-4 text-slate-400" />
                                    {new Date(scan.started_at).toLocaleString()}
                                </p>
                            </div>
                            {scan.status === 'running' && scan.progress !== undefined && (
                                <div className="pt-4 border-t">
                                    <div className="flex justify-between items-center mb-2">
                                        <p className="text-sm font-medium">Progress</p>
                                        <p className="text-sm font-bold text-blue-600">{scan.progress}%</p>
                                    </div>
                                    <Progress value={scan.progress} className="h-2" />
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-medium">Summary</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="grid grid-cols-2 gap-4">
                                <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                                    <p className="text-xs text-red-600 dark:text-red-400 font-medium">Critical</p>
                                    <p className="text-2xl font-bold">{vulnerabilities.filter(v => v.severity === 'critical').length}</p>
                                </div>
                                <div className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                                    <p className="text-xs text-orange-600 dark:text-orange-400 font-medium">High</p>
                                    <p className="text-2xl font-bold">{vulnerabilities.filter(v => v.severity === 'high').length}</p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>

                <div className="lg:col-span-2">
                    <Card className="min-h-[500px]">
                        <CardHeader className="flex flex-row items-center justify-between border-b pb-4">
                            <div>
                                <CardTitle className="text-xl">Vulnerabilities Found</CardTitle>
                                <CardDescription>Comprehensive list of security findings</CardDescription>
                            </div>
                            <Badge variant="outline" className="h-6">
                                {vulnerabilities.length} Total
                            </Badge>
                        </CardHeader>
                        <CardContent className="p-0">
                            {loading ? (
                                <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                                    <Loader2 className="h-8 w-8 animate-spin mb-4" />
                                    <p>Loading scan results...</p>
                                </div>
                            ) : vulnerabilities.length === 0 ? (
                                <div className="flex flex-col items-center justify-center py-20 text-slate-400">
                                    <CheckCircle2 className="h-12 w-12 mb-4 text-green-500" />
                                    <h3 className="text-lg font-medium text-slate-900 dark:text-white">No vulnerabilities found</h3>
                                    <p>Great! No security issues were identified in this scan yet.</p>
                                </div>
                            ) : (
                                <div className="divide-y">
                                    {vulnerabilities.map((vuln) => (
                                        <div
                                            key={vuln.id}
                                            className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer flex items-center justify-between group"
                                            onClick={() => onSelectVulnerability(vuln)}
                                        >
                                            <div className="space-y-1 pr-4">
                                                <div className="flex items-center gap-2">
                                                    <Badge variant={getSeverityColor(vuln.severity)} className="text-[10px] px-1.5 py-0 h-4">
                                                        {vuln.severity.toUpperCase()}
                                                    </Badge>
                                                    <h4 className="font-semibold text-slate-900 dark:text-white group-hover:text-blue-600 transition-colors">
                                                        {vuln.title}
                                                    </h4>
                                                </div>
                                                <div className="flex items-center gap-3 text-xs text-slate-500">
                                                    <span className="flex items-center gap-1">
                                                        <Activity className="h-3 w-3" />
                                                        {vuln.tool_name}
                                                    </span>
                                                    <span className="flex items-center gap-1 truncate max-w-[200px]">
                                                        <Target className="h-3 w-3" />
                                                        {vuln.endpoint || 'Root'}
                                                    </span>
                                                </div>
                                            </div>
                                            <ChevronRight className="h-5 w-5 text-slate-300 group-hover:text-blue-600 transform group-hover:translate-x-1 transition-all" />
                                        </div>
                                    ))}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            </div>
        </div>
    )
}
