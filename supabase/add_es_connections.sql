-- Saved Elasticsearch connection configs
CREATE TABLE es_connections (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL,
  label       text NOT NULL,
  connect_mode text NOT NULL DEFAULT 'cloud',  -- 'cloud' | 'url'
  es_url      text,
  cloud_id    text,
  api_key     text,
  suricata_index text NOT NULL DEFAULT 'filebeat-*',
  winlog_index   text NOT NULL DEFAULT 'winlogbeat-*',
  poll_interval  int NOT NULL DEFAULT 30,
  max_polls      int NOT NULL DEFAULT 10,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_es_connections_user ON es_connections(user_id);

ALTER TABLE es_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own connections"
  ON es_connections FOR ALL TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Link live runs to their connection + track poll state
ALTER TABLE correlation_runs
  ADD COLUMN connection_id uuid REFERENCES es_connections(id) ON DELETE SET NULL,
  ADD COLUMN poll_count    int NOT NULL DEFAULT 0,
  ADD COLUMN last_poll_at  timestamptz;
