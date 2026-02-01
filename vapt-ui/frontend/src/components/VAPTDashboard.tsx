import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  Download,
  Eye,
  Loader2,
  RefreshCw
} from 'lucide-react';

const VAPTDashboard = () => {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);

  // API base URL
  const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  // Load scans on component mount
  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const response = await fetch(`${API_URL}/api/scans`);
      const data = await response.json();
      setScans(data.scans || []);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load scans:', error);
      setLoading(false);
    }
  };

  const loadVulnerabilities = async (scanId) => {
    try {
      const response = await fetch(`${API_URL}/api/scans/${scanId}/vulnerabilities`);
      const data = await response.json();
      setVulnerabilities(data.vulnerabilities || []);
    } catch (error) {
      console.error('Failed to load vulnerabilities:', error);
    }
  };

  const loadRemediation = async (vulnId) => {
    setRemediationLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/vulnerabilities/${vulnId}/remediation`);
      const data = await response.json();
      setRemediation(data);
    } catch (error) {
      console.error('Failed to load remediation:', error);
      setRemediation({ error: 'Failed to load AI remediation' });
    } finally {
      setRemediationLoading(false);
    }
  };

  const startNewScan = async () => {
    const targetDomain = prompt('Enter target domain:');
    if (!targetDomain) return;

    try {
      const response = await fetch(`${API_URL}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_domain: targetDomain })
      });
      
      if (response.ok) {
        loadScans();
        alert('Scan started successfully!');
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan');
    }
  };

  const generateReport = async (scanId, format = 'pdf') => {
    try {
      const response = await fetch(`${API_URL}/api/scans/${scanId}/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format })
      });
      
      if (response.ok) {
        alert('Report generation started!');
      }
    } catch (error) {
      console.error('Failed to generate report:', error);
      alert('Failed to generate report');
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      case 'info': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'running': return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      case 'failed': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default: return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">VAPT Dashboard</h1>
            <p className="text-gray-600 mt-2">Vulnerability Assessment and Penetration Testing</p>
          </div>
          <div className="flex gap-4">
            <Button onClick={startNewScan} className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              New Scan
            </Button>
            <Button variant="outline" onClick={loadScans} className="flex items-center gap-2">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Scans List */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle>Recent Scans</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="flex justify-center py-4">
                    <Loader2 className="h-6 w-6 animate-spin" />
                  </div>
                ) : (
                  <div className="space-y-2">
                    {scans.map((scan) => (
                      <div
                        key={scan.id}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          selectedScan?.id === scan.id ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:bg-gray-50'
                        }`}
                        onClick={() => {
                          setSelectedScan(scan);
                          loadVulnerabilities(scan.id);
                        }}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            {getStatusIcon(scan.status)}
                            <span className="font-medium text-sm">{scan.target_domain}</span>
                          </div>
                          <Badge variant="outline" className="text-xs">
                            {scan.status}
                          </Badge>
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {new Date(scan.started_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Vulnerabilities Details */}
          <div className="lg:col-span-2">
            {selectedScan ? (
              <Tabs defaultValue="vulnerabilities" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="details">Scan Details</TabsTrigger>
                  <TabsTrigger value="reports">Reports</TabsTrigger>
                </TabsList>

                <TabsContent value="vulnerabilities" className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-semibold">Vulnerabilities Found</h3>
                    <div className="flex gap-2">
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => generateReport(selectedScan.id, 'pdf')}
                      >
                        <Download className="h-4 w-4 mr-2" />
                        PDF
                      </Button>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => generateReport(selectedScan.id, 'docx')}
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Word
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-3">
                    {vulnerabilities.map((vuln) => (
                      <Card key={vuln.id} className="cursor-pointer hover:shadow-md transition-shadow">
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <Badge className={`text-white ${getSeverityColor(vuln.severity)}`}>
                                  {vuln.severity}
                                </Badge>
                                <span className="font-medium">{vuln.title}</span>
                              </div>
                              <div className="text-sm text-gray-600 mb-2">
                                <strong>Tool:</strong> {vuln.tool_name} | 
                                <strong> Endpoint:</strong> {vuln.endpoint || 'N/A'}
                              </div>
                              <p className="text-sm text-gray-700 line-clamp-2">
                                {vuln.description}
                              </p>
                            </div>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setSelectedVuln(vuln);
                                loadRemediation(vuln.id);
                              }}
                              className="ml-4"
                            >
                              <Eye className="h-4 w-4 mr-2" />
                              AI Remediation
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="details">
                  <Card>
                    <CardContent className="p-6">
                      <h3 className="text-lg font-semibold mb-4">Scan Details</h3>
                      <div className="space-y-3">
                        <div><strong>Target:</strong> {selectedScan.target_domain}</div>
                        <div><strong>Type:</strong> {selectedScan.scan_type}</div>
                        <div><strong>Status:</strong> {selectedScan.status}</div>
                        <div><strong>Started:</strong> {new Date(selectedScan.started_at).toLocaleString()}</div>
                        {selectedScan.completed_at && (
                          <div><strong>Completed:</strong> {new Date(selectedScan.completed_at).toLocaleString()}</div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="reports">
                  <Card>
                    <CardContent className="p-6">
                      <h3 className="text-lg font-semibold mb-4">Generate Reports</h3>
                      <div className="grid grid-cols-2 gap-4">
                        <Button 
                          onClick={() => generateReport(selectedScan.id, 'pdf')}
                          className="flex items-center gap-2"
                        >
                          <Download className="h-4 w-4" />
                          Generate PDF Report
                        </Button>
                        <Button 
                          onClick={() => generateReport(selectedScan.id, 'docx')}
                          variant="outline"
                          className="flex items-center gap-2"
                        >
                          <Download className="h-4 w-4" />
                          Generate Word Report
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            ) : (
              <Card>
                <CardContent className="p-12 text-center">
                  <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">No Scan Selected</h3>
                  <p className="text-gray-600">Select a scan from the list to view vulnerabilities</p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* AI Remediation Modal */}
        {selectedVuln && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <Card className="max-w-2xl w-full max-h-[80vh] overflow-y-auto">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  AI Remediation: {selectedVuln.title}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {remediationLoading ? (
                  <div className="flex justify-center py-8">
                    <Loader2 className="h-8 w-8 animate-spin" />
                  </div>
                ) : remediation ? (
                  <div className="space-y-4">
                    {remediation.error ? (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{remediation.error}</AlertDescription>
                      </Alert>
                    ) : (
                      <>
                        <div>
                          <h4 className="font-semibold mb-2">Vulnerability Details</h4>
                          <div className="bg-gray-50 p-3 rounded-lg">
                            <p><strong>Severity:</strong> {selectedVuln.severity}</p>
                            <p><strong>Tool:</strong> {selectedVuln.tool_name}</p>
                            <p><strong>Endpoint:</strong> {selectedVuln.endpoint}</p>
                          </div>
                        </div>
                        
                        {remediation.findings && remediation.findings[0] && (
                          <div>
                            <h4 className="font-semibold mb-2">AI Remediation Steps</h4>
                            <div className="bg-blue-50 p-4 rounded-lg">
                              <p className="whitespace-pre-line text-sm">
                                {remediation.findings[0].remediation}
                              </p>
                            </div>
                          </div>
                        )}
                        
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" onClick={() => setSelectedVuln(null)}>
                            Close
                          </Button>
                          <Button onClick={() => generateReport(selectedScan.id, 'pdf')}>
                            <Download className="h-4 w-4 mr-2" />
                            Download with Remediation
                          </Button>
                        </div>
                      </>
                    )}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default VAPTDashboard;
