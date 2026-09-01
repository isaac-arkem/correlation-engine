export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type Database = {
  public: {
    Tables: {
      es_connections: {
        Row: {
          id: string;
          user_id: string;
          label: string;
          connect_mode: 'cloud' | 'url';
          es_url: string | null;
          cloud_id: string | null;
          api_key: string | null;
          suricata_index: string;
          winlog_index: string;
          poll_interval: number;
          max_polls: number;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          label: string;
          connect_mode?: 'cloud' | 'url';
          es_url?: string | null;
          cloud_id?: string | null;
          api_key?: string | null;
          suricata_index?: string;
          winlog_index?: string;
          poll_interval?: number;
          max_polls?: number;
          created_at?: string;
        };
        Update: Partial<Database['public']['Tables']['es_connections']['Insert']>;
        Relationships: [];
      };
      correlation_runs: {
        Row: {
          id: string;
          label: string;
          source_type: string;
          attacker_ips: string[];
          victim_ips: string[];
          c2_ports: number[];
          event_count: number;
          incident_count: number;
          source_counts: Record<string, number> | null;
          phase_counts: Record<string, number> | null;
          status: 'running' | 'completed' | 'failed';
          error: string | null;
          connection_id: string | null;
          poll_count: number;
          last_poll_at: string | null;
          created_at: string;
          completed_at: string | null;
        };
        Insert: {
          id?: string;
          label: string;
          source_type?: string;
          attacker_ips: string[];
          victim_ips: string[];
          connection_id?: string | null;
          poll_count?: number;
          last_poll_at?: string | null;
          c2_ports: number[];
          event_count?: number;
          incident_count?: number;
          source_counts?: Record<string, number> | null;
          phase_counts?: Record<string, number> | null;
          status?: 'running' | 'completed' | 'failed';
          error?: string | null;
          created_at?: string;
          completed_at?: string | null;
        };
        Update: Partial<Database['public']['Tables']['correlation_runs']['Insert']>;
        Relationships: [];
      };
      events: {
        Row: {
          id: string;
          run_id: string;
          source: 'suricata' | 'windows_security' | 'powershell';
          event_time: string;
          event_type: string | null;
          event_id: number | null;
          src_ip: string | null;
          dest_ip: string | null;
          src_port: number | null;
          dest_port: number | null;
          proto: string | null;
          signature: string | null;
          category: string | null;
          message: string | null;
          kill_chain_phase: string | null;
        };
        Insert: {
          id?: string;
          run_id: string;
          source: 'suricata' | 'windows_security' | 'powershell';
          event_time: string;
          event_type?: string | null;
          event_id?: number | null;
          src_ip?: string | null;
          dest_ip?: string | null;
          src_port?: number | null;
          dest_port?: number | null;
          proto?: string | null;
          signature?: string | null;
          category?: string | null;
          message?: string | null;
          kill_chain_phase?: string | null;
        };
        Update: Partial<Database['public']['Tables']['events']['Insert']>;
        Relationships: [];
      };
      incidents: {
        Row: {
          id: string;
          run_id: string;
          attacker_ip: string;
          victim_ip: string;
          first_seen: string;
          last_seen: string;
          phases_detected: string[];
          phase_count: number;
          risk_score: number;
          severity: 'low' | 'medium' | 'high' | 'critical';
          event_count: number;
          summary: string;
          status: 'new' | 'investigating' | 'resolved' | 'false_positive';
          status_changed_at: string | null;
          status_changed_by: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          run_id: string;
          attacker_ip: string;
          victim_ip: string;
          first_seen: string;
          last_seen: string;
          phases_detected: string[];
          phase_count: number;
          risk_score: number;
          severity: 'low' | 'medium' | 'high' | 'critical';
          event_count: number;
          summary: string;
          status?: 'new' | 'investigating' | 'resolved' | 'false_positive';
          status_changed_at?: string | null;
          status_changed_by?: string | null;
          created_at?: string;
        };
        Update: Partial<Database['public']['Tables']['incidents']['Insert']>;
        Relationships: [];
      };
      incident_events: {
        Row: {
          incident_id: string;
          event_id: string;
          phase: string | null;
        };
        Insert: {
          incident_id: string;
          event_id: string;
          phase?: string | null;
        };
        Update: Partial<Database['public']['Tables']['incident_events']['Insert']>;
        Relationships: [
          {
            foreignKeyName: 'incident_events_incident_id_fkey';
            columns: ['incident_id'];
            isOneToOne: false;
            referencedRelation: 'incidents';
            referencedColumns: ['id'];
          },
          {
            foreignKeyName: 'incident_events_event_id_fkey';
            columns: ['event_id'];
            isOneToOne: false;
            referencedRelation: 'events';
            referencedColumns: ['id'];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      get_event_counts_by_source: {
        Args: { p_run_id: string; from_date?: string | null; to_date?: string | null };
        Returns: { source: string; cnt: number }[];
      };
      get_event_counts_by_phase: {
        Args: { p_run_id: string; from_date?: string | null; to_date?: string | null };
        Returns: { phase: string; cnt: number }[];
      };
      get_incident_phase_breakdown: {
        Args: { p_incident_id: string };
        Returns: Json;
      };
      get_incident_events: {
        Args: { p_incident_id: string; max_non_recon?: number; max_recon?: number };
        Returns: Database['public']['Tables']['events']['Row'][];
      };
    };
    Enums: {
      source_t: 'suricata' | 'windows_security' | 'powershell';
      severity_t: 'low' | 'medium' | 'high' | 'critical';
      incident_status_t: 'new' | 'investigating' | 'resolved' | 'false_positive';
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};
