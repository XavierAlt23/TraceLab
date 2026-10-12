-- Solo estado de protección; no modifica evidencias ni firmas existentes.
CREATE TABLE request_limits (
  bucket_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL CHECK(request_count > 0)
);
CREATE TABLE mutation_guards (
  guard_id TEXT PRIMARY KEY,
  allowed INTEGER NOT NULL CHECK(allowed = 1)
);
