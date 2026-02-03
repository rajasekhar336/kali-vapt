<?php
// Dashboard for Finding Focus VAPT
// PHP + PostgreSQL Implementation

require_once '../config/database.php';
require_once '../src/utils/auth.php';
require_once '../src/controllers/DashboardController.php';

// Require login
$auth->requireLogin();

// Initialize controllers
$dashboardController = new DashboardController($db);

// Get dashboard data
$stats = $dashboardController->getDashboardStats();
$currentUser = $auth->getCurrentUser();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Finding Focus VAPT</title>
    <link rel="stylesheet" href="css/production.css">
    <link rel="icon" type="image/x-icon" href="images/favicon.ico">
</head>
<body class="dark-theme">
    <div class="animated-background">
        <div class="floating-particles"></div>
        <div class="gradient-orbs"></div>
    </div>
    
    <div class="app-container">
        <!-- Navigation Header -->
        <nav class="navbar glassmorphism">
            <div class="nav-container">
                <div class="nav-brand">
                    <div class="brand-icon">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 2L2 7L12 12L22 7L12 2Z"></path>
                            <path d="M2 17L12 22L22 17"></path>
                            <path d="M2 12L12 17L22 12"></path>
                        </svg>
                    </div>
                    <span class="brand-name">Finding Focus VAPT</span>
                </div>
                
                <div class="nav-menu">
                    <a href="dashboard.php" class="nav-item active">Dashboard</a>
                    <a href="scans.php" class="nav-item">Scans</a>
                    <a href="vulnerabilities.php" class="nav-item">Vulnerabilities</a>
                    <a href="reports.php" class="nav-item">Reports</a>
                </div>
                
                <div class="nav-user">
                    <div class="user-menu">
                        <button class="user-button">
                            <div class="user-avatar"><?php echo strtoupper(substr($currentUser['full_name'], 0, 1)); ?></div>
                            <span class="user-name"><?php echo htmlspecialchars($currentUser['full_name']); ?></span>
                        </button>
                        <div class="user-dropdown">
                            <a href="profile.php" class="dropdown-item">Profile</a>
                            <a href="settings.php" class="dropdown-item">Settings</a>
                            <a href="logout.php" class="dropdown-item">Logout</a>
                        </div>
                    </div>
                </div>
            </div>
        </nav>
        
        <!-- Main Content -->
        <main class="main-content">
            <div class="content-container">
                <!-- Page Header -->
                <div class="page-header">
                    <div class="header-content">
                        <h1 class="page-title">Security Dashboard</h1>
                        <p class="page-subtitle">Enterprise Vulnerability Assessment Platform</p>
                    </div>
                    <div class="header-actions">
                        <button class="btn btn-secondary" onclick="refreshDashboard()">Refresh</button>
                        <a href="scans.php?action=new" class="btn btn-primary">New Scan</a>
                    </div>
                </div>
                
                <!-- Stats Grid -->
                <div class="stats-grid">
                    <div class="stat-card primary">
                        <div class="stat-icon">📊</div>
                        <div class="stat-content">
                            <div class="stat-value"><?php echo number_format($stats['scans']['total_scans']); ?></div>
                            <div class="stat-label">Total Scans</div>
                            <div class="stat-change">
                                <span class="change-positive"><?php echo $stats['scans']['running_scans']; ?> active</span>
                                <span class="change-neutral"><?php echo $stats['scans']['completed_scans']; ?> completed</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="stat-card warning">
                        <div class="stat-icon">⚠️</div>
                        <div class="stat-content">
                            <div class="stat-value"><?php echo number_format($stats['vulnerabilities']['total_vulnerabilities']); ?></div>
                            <div class="stat-label">Vulnerabilities</div>
                            <div class="stat-change">
                                <span class="change-negative"><?php echo $stats['vulnerabilities']['open_vulnerabilities']; ?> open</span>
                                <span class="change-positive"><?php echo $stats['vulnerabilities']['resolved_vulnerabilities']; ?> resolved</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="stat-card danger">
                        <div class="stat-icon">🚨</div>
                        <div class="stat-content">
                            <div class="stat-value"><?php echo number_format($stats['vulnerabilities']['critical_vulnerabilities']); ?></div>
                            <div class="stat-label">Critical Issues</div>
                            <div class="stat-change">
                                <span class="change-negative">Critical</span>
                                <span class="change-warning">+<?php echo $stats['vulnerabilities']['high_vulnerabilities']; ?> high</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="stat-card success">
                        <div class="stat-icon">🌐</div>
                        <div class="stat-content">
                            <div class="stat-value"><?php echo count($stats['domains']); ?></div>
                            <div class="stat-label">Domains</div>
                            <div class="stat-change">
                                <span class="change-positive">Security Score</span>
                                <span class="change-neutral"><?php echo $stats['security_score']; ?>/100</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Quick Actions & Security Score -->
                <div class="dashboard-grid">
                    <div class="card glassmorphism">
                        <div class="card-header">
                            <h2 class="card-title">🚀 Quick Actions</h2>
                        </div>
                        <div class="card-content">
                            <div class="action-grid">
                                <a href="scans.php?action=new" class="action-card">
                                    <h3>🛡️ Start Security Scan</h3>
                                    <p>Launch new vulnerability assessment</p>
                                </a>
                                <a href="vulnerabilities.php" class="action-card">
                                    <h3>⚠️ View Vulnerabilities</h3>
                                    <p>Manage security issues and findings</p>
                                </a>
                                <a href="reports.php" class="action-card">
                                    <h3>📋 Generate Reports</h3>
                                    <p>Create professional security reports</p>
                                </a>
                                <a href="settings.php" class="action-card">
                                    <h3>⚙️ Manage Settings</h3>
                                    <p>Configure platform and tools</p>
                                </a>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card glassmorphism">
                        <div class="card-header">
                            <h2 class="card-title">🌐 Security Score</h2>
                        </div>
                        <div class="card-content">
                            <div class="score-display">
                                <div class="score-value"><?php echo $stats['security_score']; ?></div>
                                <div class="score-label">Overall Security Score</div>
                            </div>
                            
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: <?php echo $stats['security_score']; ?>%"></div>
                            </div>
                            
                            <div class="alert <?php echo $stats['vulnerabilities']['critical_vulnerabilities'] > 0 ? 'alert-warning' : 'alert-success'; ?>">
                                <?php 
                                if ($stats['vulnerabilities']['critical_vulnerabilities'] > 0) {
                                    echo '⚠️ ' . $stats['vulnerabilities']['critical_vulnerabilities'] . ' critical issues need immediate attention';
                                } else {
                                    echo '✅ No critical vulnerabilities detected';
                                }
                                ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent Activity -->
                <div class="card glassmorphism">
                    <div class="card-header">
                        <h2 class="card-title">🕒 Recent Activity</h2>
                    </div>
                    <div class="card-content">
                        <?php if (count($stats['recent_activity']) > 0): ?>
                            <div class="activity-list">
                                <?php foreach ($stats['recent_activity'] as $activity): ?>
                                    <div class="activity-item">
                                        <div class="activity-content">
                                            <div class="activity-title">
                                                Scan <?php echo $activity['status']; ?> for <?php echo htmlspecialchars($activity['target_domain']); ?>
                                            </div>
                                            <div class="activity-meta">
                                                <span class="activity-user"><?php echo htmlspecialchars($activity['created_by_username']); ?></span>
                                                <span class="activity-time"><?php echo date('M j, Y H:i', strtotime($activity['started_at'])); ?></span>
                                            </div>
                                        </div>
                                        <div class="activity-status">
                                            <span class="status-badge <?php echo $activity['status']; ?>">
                                                <?php echo ucfirst($activity['status']); ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <div class="empty-state">
                                <p>🕒 No recent activity</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </main>
    </div>
    
    <script>
        function refreshDashboard() {
            location.reload();
        }
        
        // User dropdown toggle
        document.addEventListener('DOMContentLoaded', function() {
            const userButton = document.querySelector('.user-button');
            const userDropdown = document.querySelector('.user-dropdown');
            
            if (userButton && userDropdown) {
                userButton.addEventListener('click', function() {
                    userDropdown.classList.toggle('show');
                });
                
                document.addEventListener('click', function(e) {
                    if (!userButton.contains(e.target) && !userDropdown.contains(e.target)) {
                        userDropdown.classList.remove('show');
                    }
                });
            }
        });
    </script>
    
    <style>
        /* Dashboard Layout Styles */
        .app-container { min-height: 100vh; position: relative; z-index: 1; }
        
        .navbar { position: sticky; top: 0; z-index: 100; padding: 16px 0; }
        
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; }
        
        .nav-brand { display: flex; align-items: center; gap: 12px; }
        
        .brand-icon { width: 40px; height: 40px; background: var(--gradient-primary); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white; }
        
        .brand-name { font-size: 18px; font-weight: 700; color: var(--text-primary); }
        
        .nav-menu { display: flex; gap: 8px; }
        
        .nav-item { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-radius: 8px; color: var(--text-secondary); text-decoration: none; transition: all var(--transition-normal); }
        
        .nav-item:hover, .nav-item.active { background: var(--glass-bg); color: var(--text-primary); }
        
        .user-button { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border: 1px solid var(--glass-border); border-radius: 8px; background: var(--glass-bg); color: var(--text-primary); cursor: pointer; }
        
        .user-avatar { width: 32px; height: 32px; background: var(--gradient-primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-weight: 600; }
        
        .user-dropdown { position: absolute; top: 100%; right: 0; margin-top: 8px; min-width: 200px; background: var(--glass-bg); backdrop-filter: var(--glass-blur); border: 1px solid var(--glass-border); border-radius: 8px; opacity: 0; visibility: hidden; transform: translateY(-10px); transition: all var(--transition-normal); }
        
        .user-dropdown.show { opacity: 1; visibility: visible; transform: translateY(0); }
        
        .dropdown-item { display: block; padding: 12px 16px; color: var(--text-secondary); text-decoration: none; transition: all var(--transition-fast); }
        
        .dropdown-item:hover { background: var(--glass-bg); color: var(--text-primary); }
        
        .main-content { padding: 24px; }
        
        .content-container { max-width: 1400px; margin: 0 auto; }
        
        .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 32px; }
        
        .page-title { font-size: 32px; font-weight: 700; color: var(--text-primary); margin-bottom: 8px; }
        
        .page-subtitle { color: var(--text-secondary); font-size: 16px; }
        
        .header-actions { display: flex; gap: 12px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; margin-bottom: 32px; }
        
        .stat-card { padding: 24px; border-radius: 16px; background: var(--glass-bg); backdrop-filter: var(--glass-blur); border: 1px solid var(--glass-border); display: flex; align-items: center; gap: 16px; transition: all var(--transition-normal); }
        
        .stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
        
        .stat-icon { font-size: 32px; }
        
        .stat-value { font-size: 28px; font-weight: 700; color: var(--text-primary); margin-bottom: 4px; }
        
        .stat-label { color: var(--text-secondary); font-size: 14px; margin-bottom: 8px; }
        
        .stat-change { display: flex; gap: 12px; font-size: 12px; }
        
        .change-positive { color: var(--accent-success); }
        .change-negative { color: var(--accent-danger); }
        .change-neutral { color: var(--text-muted); }
        .change-warning { color: var(--accent-warning); }
        
        .dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 32px; }
        
        .card { border-radius: 16px; padding: 24px; }
        
        .card-title { font-size: 18px; font-weight: 600; color: var(--text-primary); margin-bottom: 20px; }
        
        .action-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
        
        .action-card { display: block; padding: 20px; border-radius: 12px; background: var(--glass-bg); border: 1px solid var(--glass-border); text-decoration: none; color: var(--text-primary); transition: all var(--transition-normal); }
        
        .action-card:hover { transform: translateY(-2px); background: rgba(255, 255, 255, 0.08); }
        
        .action-card h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
        
        .action-card p { font-size: 12px; color: var(--text-muted); }
        
        .score-display { text-align: center; margin-bottom: 24px; }
        
        .score-value { font-size: 48px; font-weight: 700; color: var(--accent-warning); margin-bottom: 8px; }
        
        .score-label { color: var(--text-secondary); font-size: 14px; }
        
        .progress-bar { height: 8px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 16px; overflow: hidden; }
        
        .progress-fill { height: 100%; background: var(--gradient-warning); border-radius: 4px; transition: width var(--transition-slow); }
        
        .alert { display: flex; align-items: center; gap: 12px; padding: 12px; border-radius: 8px; font-size: 14px; }
        
        .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #6ee7b7; }
        
        .alert-warning { background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); color: #fcd34d; }
        
        .activity-list { display: flex; flex-direction: column; gap: 16px; }
        
        .activity-item { display: flex; align-items: center; justify-content: space-between; padding: 16px; border-radius: 12px; background: var(--glass-bg); border: 1px solid var(--glass-border); }
        
        .activity-title { font-weight: 500; color: var(--text-primary); margin-bottom: 4px; }
        
        .activity-meta { display: flex; gap: 16px; font-size: 12px; color: var(--text-muted); }
        
        .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        
        .status-badge.completed { background: rgba(16, 185, 129, 0.2); color: var(--accent-success); }
        
        .status-badge.running { background: rgba(245, 158, 11, 0.2); color: var(--accent-warning); }
        
        .status-badge.failed { background: rgba(239, 68, 68, 0.2); color: var(--accent-danger); }
        
        .empty-state { text-align: center; padding: 40px; color: var(--text-muted); }
        
        .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 20px; border: none; border-radius: 8px; font-size: 14px; font-weight: 500; text-decoration: none; cursor: pointer; transition: all var(--transition-normal); }
        
        .btn-primary { background: var(--gradient-primary); color: white; }
        
        .btn-secondary { background: var(--glass-bg); color: var(--text-primary); border: 1px solid var(--glass-border); }
        
        .btn:hover { transform: translateY(-1px); }
        
        @media (max-width: 768px) {
            .nav-menu { display: none; }
            .dashboard-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
            .page-header { flex-direction: column; gap: 16px; align-items: flex-start; }
        }
    </style>
</body>
</html>
