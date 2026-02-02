export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      domains: {
        Row: {
          created_at: string
          current_phase: string | null
          domain_name: string
          id: string
          phase_progress: number | null
          scan_status: Database["public"]["Enums"]["scan_status"]
          security_score: number | null
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          current_phase?: string | null
          domain_name: string
          id?: string
          phase_progress?: number | null
          scan_status?: Database["public"]["Enums"]["scan_status"]
          security_score?: number | null
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          current_phase?: string | null
          domain_name?: string
          id?: string
          phase_progress?: number | null
          scan_status?: Database["public"]["Enums"]["scan_status"]
          security_score?: number | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      findings: {
        Row: {
          affected_url: string | null
          created_at: string
          cvss_score: number | null
          cwe_id: string | null
          description: string | null
          domain_id: string
          evidence: string | null
          id: string
          notes: string | null
          owasp_category: string | null
          remediation: string | null
          risk_status: Database["public"]["Enums"]["risk_status"]
          scan_id: string | null
          severity: Database["public"]["Enums"]["severity_level"]
          title: string
          tool: string | null
          updated_at: string
          validation_status: Database["public"]["Enums"]["validation_status"]
        }
        Insert: {
          affected_url?: string | null
          created_at?: string
          cvss_score?: number | null
          cwe_id?: string | null
          description?: string | null
          domain_id: string
          evidence?: string | null
          id?: string
          notes?: string | null
          owasp_category?: string | null
          remediation?: string | null
          risk_status?: Database["public"]["Enums"]["risk_status"]
          scan_id?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          title: string
          tool?: string | null
          updated_at?: string
          validation_status?: Database["public"]["Enums"]["validation_status"]
        }
        Update: {
          affected_url?: string | null
          created_at?: string
          cvss_score?: number | null
          cwe_id?: string | null
          description?: string | null
          domain_id?: string
          evidence?: string | null
          id?: string
          notes?: string | null
          owasp_category?: string | null
          remediation?: string | null
          risk_status?: Database["public"]["Enums"]["risk_status"]
          scan_id?: string | null
          severity?: Database["public"]["Enums"]["severity_level"]
          title?: string
          tool?: string | null
          updated_at?: string
          validation_status?: Database["public"]["Enums"]["validation_status"]
        }
        Relationships: [
          {
            foreignKeyName: "findings_domain_id_fkey"
            columns: ["domain_id"]
            isOneToOne: false
            referencedRelation: "domains"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "findings_scan_id_fkey"
            columns: ["scan_id"]
            isOneToOne: false
            referencedRelation: "scans"
            referencedColumns: ["id"]
          },
        ]
      }
      profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          full_name: string | null
          id: string
          updated_at: string
          user_id: string
          username: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          full_name?: string | null
          id?: string
          updated_at?: string
          user_id: string
          username: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          full_name?: string | null
          id?: string
          updated_at?: string
          user_id?: string
          username?: string
        }
        Relationships: []
      }
      scans: {
        Row: {
          completed_at: string | null
          current_phase: string | null
          domain_id: string
          findings_count: number | null
          id: string
          started_at: string
          status: Database["public"]["Enums"]["scan_status"]
          tools_used: string[] | null
        }
        Insert: {
          completed_at?: string | null
          current_phase?: string | null
          domain_id: string
          findings_count?: number | null
          id?: string
          started_at?: string
          status?: Database["public"]["Enums"]["scan_status"]
          tools_used?: string[] | null
        }
        Update: {
          completed_at?: string | null
          current_phase?: string | null
          domain_id?: string
          findings_count?: number | null
          id?: string
          started_at?: string
          status?: Database["public"]["Enums"]["scan_status"]
          tools_used?: string[] | null
        }
        Relationships: [
          {
            foreignKeyName: "scans_domain_id_fkey"
            columns: ["domain_id"]
            isOneToOne: false
            referencedRelation: "domains"
            referencedColumns: ["id"]
          },
        ]
      }
      user_roles: {
        Row: {
          created_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "analyst" | "viewer"
      risk_status: "open" | "mitigated" | "accepted"
      scan_status: "queued" | "scanning" | "completed" | "failed"
      severity_level: "critical" | "high" | "medium" | "low" | "info"
      validation_status:
        | "pending"
        | "validated"
        | "false_positive"
        | "needs_review"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "analyst", "viewer"],
      risk_status: ["open", "mitigated", "accepted"],
      scan_status: ["queued", "scanning", "completed", "failed"],
      severity_level: ["critical", "high", "medium", "low", "info"],
      validation_status: [
        "pending",
        "validated",
        "false_positive",
        "needs_review",
      ],
    },
  },
} as const
