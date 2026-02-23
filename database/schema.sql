CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  provider TEXT NOT NULL,                 -- aws/gcp/azure/network
  asset_type TEXT NOT NULL,               -- ec2/s3/ip/host/container
  asset_id TEXT NOT NULL,                 -- instance-id, bucket-name, ip
  name TEXT,
  region TEXT,
  account_id TEXT,
  public_exposure BOOLEAN DEFAULT FALSE,
  tags JSONB DEFAULT '{}'::jsonb,
  metadata JSONB DEFAULT '{}'::jsonb,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(provider, asset_type, asset_id)
);

CREATE TABLE IF NOT EXISTS risk_scores (
  id SERIAL PRIMARY KEY,
  provider TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  risk_score NUMERIC(4,2) NOT NULL,
  reasons JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);