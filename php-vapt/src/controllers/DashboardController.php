<?php
// Simplified Dashboard Controller for Finding Focus VAPT
// PHP + PostgreSQL Implementation

class DashboardController {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function getDashboardStats() {
        $stats = [];
        
        // Get scan statistics
        $scanStats = $this->db->fetch("
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans,
                COUNT(CASE WHEN status = 'running' THEN 1 END) as running_scans,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans
            FROM scans
        ");
        $stats['scans'] = $scanStats;
        
        // Get vulnerability statistics
        $vulnStats = $this->db->fetch("
            SELECT 
                COUNT(*) as total_vulnerabilities,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_vulnerabilities,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_vulnerabilities,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_vulnerabilities,
                COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_vulnerabilities,
                COUNT(CASE WHEN status = 'open' THEN 1 END) as open_vulnerabilities,
                COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_vulnerabilities
            FROM vulnerabilities
        ");
        $stats['vulnerabilities'] = $vulnStats;
        
        // Get domain statistics
        $domainStats = $this->db->fetchAll("
            SELECT 
                s.target_domain,
                COUNT(DISTINCT s.id) as scan_count,
                COUNT(DISTINCT v.id) as vulnerability_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'critical' THEN v.id END) as critical_count,
                COUNT(DISTINCT CASE WHEN v.severity = 'high' THEN v.id END) as high_count
            FROM scans s
            LEFT JOIN vulnerabilities v ON s.id = v.scan_id
            GROUP BY s.target_domain
            ORDER BY vulnerability_count DESC
            LIMIT 10
        ");
        $stats['domains'] = $domainStats;
        
        // Get recent activity
        $recentActivity = $this->db->fetchAll("
            SELECT s.id, s.target_domain, s.status, s.created_at, u.username
            FROM scans s
            JOIN users u ON s.created_by = u.id
            ORDER BY s.created_at DESC
            LIMIT 5
        ");
        $stats['recent_activity'] = $recentActivity;
        
        // Calculate security score
        $totalVulns = $vulnStats['total_vulnerabilities'];
        $criticalVulns = $vulnStats['critical_vulnerabilities'];
        $highVulns = $vulnStats['high_vulnerabilities'];
        
        if ($totalVulns == 0) {
            $securityScore = 100;
        } else {
            $weightedScore = ($criticalVulns * 10) + ($highVulns * 5) + ($totalVulns - $criticalVulns - $highVulns);
            $securityScore = max(0, 100 - $weightedScore);
        }
        
        $stats['security_score'] = $securityScore;
        
        return $stats;
    }
}
