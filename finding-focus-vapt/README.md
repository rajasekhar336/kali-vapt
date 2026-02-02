# VAPT Web UI Architecture

## 🎯 System Overview
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend UI   │────│  Backend API     │────│  Tool Services  │
│                 │    │                  │    │                 │
│ • Dashboard     │    │ • Scan Manager   │    │ • Nmap          │
│ • Vulnerability │    │ • Normalizer     │    │ • Nuclei        │
│ • Reports       │    │ • AI Service     │    │ • ZAP           │
│ • Settings      │    │ • Report Gen     │    │ • Nikto         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🔧 Backend Services

### 1. Tool Execution Service
- Runs all security tools in Docker containers
- Manages parallel execution and resource monitoring
- Stores raw outputs in structured format

### 2. Normalization Service
- Converts tool outputs to standardized JSON format
- Categorizes vulnerabilities by type and severity
- Maintains vulnerability database

### 3. AI Remediation Service
- On-demand AI analysis for clicked vulnerabilities
- Detailed remediation steps and best practices
- Cached results for performance

### 4. Report Generation Service
- PDF/Word document generation
- Includes vulnerability details and AI remediation
- Customizable templates and branding

## 🎨 Frontend Components

### 1. Dashboard
- Vulnerability overview with charts
- Severity distribution
- Recent scans and status
- Quick actions and filters

### 2. Vulnerability Details
- Expandable vulnerability cards
- Click-to-reveal AI remediation
- Affected endpoints and evidence
- Related vulnerabilities

### 3. Scan Management
- Start new scans with target configuration
- Monitor scan progress in real-time
- Scan history and scheduling
- Tool configuration and settings

### 4. Reports & Export
- Download reports with AI remediation
- Custom report templates
- Export formats (PDF, Word, JSON, CSV)
- Share and collaboration features

## 🏗️ Technology Stack

### Backend
- **Framework**: Flask/FastAPI (Python)
- **Database**: PostgreSQL + Redis (caching)
- **Queue**: Celery for background tasks
- **Container**: Docker + Docker Compose

### Frontend
- **Framework**: React + TypeScript
- **UI Library**: Tailwind CSS + shadcn/ui
- **Charts**: Chart.js / Recharts
- **State**: Redux Toolkit

### AI Integration
- **Service**: Existing Qwen 0.5B normalizer
- **API**: RESTful endpoints for AI requests
- **Caching**: Redis for AI responses

## 📊 Data Flow

1. **User starts scan** → Backend queues tool execution
2. **Tools run** → Raw outputs stored in database
3. **Normalization** → Standardized vulnerability format
4. **Dashboard display** → Vulnerabilities shown without AI
5. **User clicks vulnerability** → AI remediation fetched
6. **Report download** → AI remediation included in document

## 🚀 Implementation Plan

### Phase 1: Backend API
- Tool execution service
- Normalization service
- Basic database schema
- AI integration endpoints

### Phase 2: Frontend Dashboard
- Vulnerability display
- Scan management
- Basic UI components

### Phase 3: AI Integration
- Click-to-reveal remediation
- Caching system
- Performance optimization

### Phase 4: Reports & Export
- PDF/Word generation
- Custom templates
- Export functionality

### Phase 5: Advanced Features
- Real-time updates
- Collaboration features
- Advanced analytics
