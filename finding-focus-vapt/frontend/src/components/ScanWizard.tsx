'use client'

import * as React from 'react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Shield, Search, Play, Download, Settings, ChevronRight, AlertCircle, CheckCircle2, Clock, Target, Zap, Globe, Lock, Eye, FileText } from 'lucide-react'

interface ScanRequest {
  target_domain: string
  scan_type: 'quick' | 'full' | 'custom'
  tools: string[]
  config?: Record<string, any>
}

interface ScanWizardProps {
  onStartScan: (request: ScanRequest) => Promise<void>
  isScanning: boolean
}

const availableTools = [
  { id: 'nuclei', name: 'Nuclei', description: 'Fast and customizable vulnerability scanner', icon: Target },
  { id: 'nikto', name: 'Nikto', description: 'Web server scanner', icon: Eye },
  { id: 'sqlmap', name: 'SQLMap', description: 'SQL injection testing tool', icon: Lock },
  { id: 'nmap', name: 'Nmap', description: 'Network discovery and security auditing', icon: Globe },
  { id: 'dirb', name: 'Dirb', description: 'Web content scanner', icon: FileText },
  { id: 'gobuster', name: 'Gobuster', description: 'Directory/file & DNS busting tool', icon: Search },
  { id: 'whatweb', name: 'WhatWeb', description: 'Web technology identifier', icon: Eye },
  { id: 'wpscan', name: 'WPScan', description: 'WordPress security scanner', icon: Lock }
]

const scanTypes = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Fast basic vulnerability assessment',
    duration: '5-10 minutes',
    tools: ['nuclei', 'nikto'],
    color: 'bg-green-500'
  },
  {
    id: 'full',
    name: 'Full Assessment',
    description: 'Comprehensive security testing',
    duration: '30-45 minutes',
    tools: ['nuclei', 'nikto', 'sqlmap', 'nmap', 'dirb', 'gobuster', 'whatweb'],
    color: 'bg-blue-500'
  },
  {
    id: 'custom',
    name: 'Custom Scan',
    description: 'Select specific tools and configuration',
    duration: 'Variable',
    tools: [],
    color: 'bg-purple-500'
  }
]

export default function ScanWizard({ onStartScan, isScanning }: ScanWizardProps) {
  const [step, setStep] = useState(1)
  const [scanRequest, setScanRequest] = useState<ScanRequest>({
    target_domain: '',
    scan_type: 'quick',
    tools: ['nuclei', 'nikto'],
    config: {}
  })

  const handleNext = () => {
    if (step < 3) setStep(step + 1)
  }

  const handleBack = () => {
    if (step > 1) setStep(step - 1)
  }

  const handleStartScan = async () => {
    await onStartScan(scanRequest)
    setStep(1)
    setScanRequest({
      target_domain: '',
      scan_type: 'quick',
      tools: ['nuclei', 'nikto'],
      config: {}
    })
  }

  const toggleTool = (toolId: string) => {
    setScanRequest(prev => ({
      ...prev,
      tools: prev.tools.includes(toolId)
        ? prev.tools.filter(t => t !== toolId)
        : [...prev.tools, toolId]
    }))
  }

  const selectScanType = (type: 'quick' | 'full' | 'custom') => {
    const selectedType = scanTypes.find(t => t.id === type)
    setScanRequest(prev => ({
      ...prev,
      scan_type: type,
      tools: type === 'custom' ? prev.tools : selectedType?.tools || []
    }))
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      {/* Progress Indicator */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          {[1, 2, 3].map((s) => (
            <div key={s} className="flex items-center">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center text-sm font-medium ${
                s <= step ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'
              }`}>
                {s < step ? <CheckCircle2 className="h-5 w-5" /> : s}
              </div>
              {s < 3 && (
                <div className={`w-24 h-1 mx-2 ${s < step ? 'bg-blue-600' : 'bg-gray-200'}`} />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between text-sm text-gray-600">
          <span>Target Selection</span>
          <span>Scan Configuration</span>
          <span>Review & Launch</span>
        </div>
      </div>

      {/* Step 1: Target Selection */}
      {step === 1 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-6 w-6" />
              Select Target
            </CardTitle>
            <CardDescription>
              Enter the domain or IP address you want to scan for vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <label className="block text-sm font-medium mb-2">Target Domain or IP</label>
              <Input
                placeholder="example.com or 192.168.1.1"
                value={scanRequest.target_domain}
                onChange={(e) => setScanRequest(prev => ({ ...prev, target_domain: e.target.value }))}
                startIcon={<Globe className="h-4 w-4" />}
                helperText="Enter a valid domain name or IP address"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-4">Scan Type</label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {scanTypes.map((type) => (
                  <div
                    key={type.id}
                    className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                      scanRequest.scan_type === type.id
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-200 hover:border-gray-300'
                    }`}
                    onClick={() => selectScanType(type.id)}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <div className={`w-3 h-3 rounded-full ${type.color}`} />
                      <h3 className="font-medium">{type.name}</h3>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{type.description}</p>
                    <div className="flex items-center gap-2 text-xs text-gray-500">
                      <Clock className="h-3 w-3" />
                      <span>{type.duration}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <Button onClick={handleNext} disabled={!scanRequest.target_domain}>
                Next
                <ChevronRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Step 2: Tool Selection */}
      {step === 2 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="h-6 w-6" />
              Configure Scan Tools
            </CardTitle>
            <CardDescription>
              {scanRequest.scan_type === 'custom' 
                ? 'Select the specific tools you want to run'
                : `Selected tools for ${scanRequest.scan_type} scan`
              }
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {scanRequest.scan_type === 'custom' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {availableTools.map((tool) => {
                  const Icon = tool.icon
                  const isSelected = scanRequest.tools.includes(tool.id)
                  return (
                    <div
                      key={tool.id}
                      className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
                        isSelected
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                      onClick={() => toggleTool(tool.id)}
                    >
                      <div className="flex items-start gap-3">
                        <Icon className="h-5 w-5 text-gray-600 mt-1" />
                        <div className="flex-1">
                          <h3 className="font-medium">{tool.name}</h3>
                          <p className="text-sm text-gray-600 mt-1">{tool.description}</p>
                        </div>
                        <div className={`w-5 h-5 rounded-full border-2 ${
                          isSelected ? 'bg-blue-600 border-blue-600' : 'border-gray-300'
                        }`}>
                          {isSelected && <CheckCircle2 className="h-4 w-4 text-white m-0.5" />}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="space-y-4">
                <div className="p-4 bg-blue-50 rounded-lg">
                  <h3 className="font-medium mb-2">Selected Tools:</h3>
                  <div className="flex flex-wrap gap-2">
                    {scanRequest.tools.map((toolId) => {
                      const tool = availableTools.find(t => t.id === toolId)
                      return (
                        <Badge key={toolId} variant="secondary">
                          {tool?.name}
                        </Badge>
                      )
                    })}
                  </div>
                </div>
                <p className="text-sm text-gray-600">
                  These tools are optimized for the selected scan type. For custom tool selection, 
                  choose "Custom Scan" in the previous step.
                </p>
              </div>
            )}

            <div className="flex justify-between">
              <Button variant="outline" onClick={handleBack}>
                Back
              </Button>
              <Button onClick={handleNext} disabled={scanRequest.tools.length === 0}>
                Next
                <ChevronRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Step 3: Review & Launch */}
      {step === 3 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-6 w-6" />
              Review & Launch Scan
            </CardTitle>
            <CardDescription>
              Review your scan configuration and start the vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="font-medium mb-3">Target Information</h3>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Target:</span>
                    <span className="font-medium">{scanRequest.target_domain}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Scan Type:</span>
                    <Badge variant="outline">{scanRequest.scan_type}</Badge>
                  </div>
                </div>
              </div>

              <div>
                <h3 className="font-medium mb-3">Selected Tools</h3>
                <div className="flex flex-wrap gap-2">
                  {scanRequest.tools.map((toolId) => {
                    const tool = availableTools.find(t => t.id === toolId)
                    return (
                      <Badge key={toolId} variant="secondary">
                        {tool?.name}
                      </Badge>
                    )
                  })}
                </div>
              </div>
            </div>

            <div className="p-4 bg-yellow-50 rounded-lg border border-yellow-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="h-5 w-5 text-yellow-600 mt-0.5" />
                <div>
                  <h4 className="font-medium text-yellow-800">Important Notice</h4>
                  <p className="text-sm text-yellow-700 mt-1">
                    This scan will perform automated security testing against the target. 
                    Ensure you have proper authorization before proceeding.
                  </p>
                </div>
              </div>
            </div>

            <div className="flex justify-between">
              <Button variant="outline" onClick={handleBack}>
                Back
              </Button>
              <Button 
                onClick={handleStartScan} 
                disabled={isScanning}
                loading={isScanning}
                className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
              >
                {isScanning ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent mr-2" />
                    Starting Scan...
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
