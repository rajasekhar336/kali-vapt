-- Create enum for roles
CREATE TYPE public.app_role AS ENUM ('admin', 'analyst', 'viewer');

-- Create enum for scan status
CREATE TYPE public.scan_status AS ENUM ('queued', 'scanning', 'completed', 'failed');

-- Create enum for severity
CREATE TYPE public.severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Create enum for validation status
CREATE TYPE public.validation_status AS ENUM ('pending', 'validated', 'false_positive', 'needs_review');

-- Create enum for risk status
CREATE TYPE public.risk_status AS ENUM ('open', 'mitigated', 'accepted');

-- Create profiles table
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
  username TEXT NOT NULL,
  full_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create user_roles table (separate from profiles for security)
CREATE TABLE public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  role app_role NOT NULL DEFAULT 'viewer',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);

-- Create domains table
CREATE TABLE public.domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  domain_name TEXT NOT NULL,
  scan_status scan_status NOT NULL DEFAULT 'queued',
  current_phase TEXT,
  phase_progress INTEGER DEFAULT 0,
  security_score INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Create scans table
CREATE TABLE public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id UUID REFERENCES public.domains(id) ON DELETE CASCADE NOT NULL,
  status scan_status NOT NULL DEFAULT 'queued',
  current_phase TEXT,
  tools_used TEXT[] DEFAULT '{}',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  findings_count INTEGER DEFAULT 0
);

-- Create findings table
CREATE TABLE public.findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain_id UUID REFERENCES public.domains(id) ON DELETE CASCADE NOT NULL,
  scan_id UUID REFERENCES public.scans(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  description TEXT,
  severity severity_level NOT NULL DEFAULT 'medium',
  validation_status validation_status NOT NULL DEFAULT 'pending',
  risk_status risk_status NOT NULL DEFAULT 'open',
  cvss_score DECIMAL(3,1),
  cwe_id TEXT,
  owasp_category TEXT,
  affected_url TEXT,
  evidence TEXT,
  remediation TEXT,
  tool TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

-- Security definer function to check roles
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = _role
  )
$$;

-- Profiles policies
CREATE POLICY "Users can view own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own profile" ON public.profiles
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- User roles policies (only admins can manage roles)
CREATE POLICY "Users can view own roles" ON public.user_roles
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Admins can manage all roles" ON public.user_roles
  FOR ALL USING (public.has_role(auth.uid(), 'admin'));

-- Domains policies
CREATE POLICY "Users can view own domains" ON public.domains
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can create domains" ON public.domains
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own domains" ON public.domains
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own domains" ON public.domains
  FOR DELETE USING (auth.uid() = user_id);

-- Scans policies (via domain ownership)
CREATE POLICY "Users can view scans for own domains" ON public.scans
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.domains WHERE domains.id = scans.domain_id AND domains.user_id = auth.uid())
  );

CREATE POLICY "Users can create scans for own domains" ON public.scans
  FOR INSERT WITH CHECK (
    EXISTS (SELECT 1 FROM public.domains WHERE domains.id = domain_id AND domains.user_id = auth.uid())
  );

-- Findings policies (via domain ownership)
CREATE POLICY "Users can view findings for own domains" ON public.findings
  FOR SELECT USING (
    EXISTS (SELECT 1 FROM public.domains WHERE domains.id = findings.domain_id AND domains.user_id = auth.uid())
  );

CREATE POLICY "Users can update findings for own domains" ON public.findings
  FOR UPDATE USING (
    EXISTS (SELECT 1 FROM public.domains WHERE domains.id = findings.domain_id AND domains.user_id = auth.uid())
  );

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER update_domains_updated_at BEFORE UPDATE ON public.domains
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON public.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- Function to create profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (user_id, username)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)));
  
  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'analyst');
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();