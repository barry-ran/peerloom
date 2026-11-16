ALTER TABLE sessions
 ADD COLUMN source_ice_count integer NOT NULL DEFAULT 0 CHECK(source_ice_count BETWEEN 0 AND 256),
 ADD COLUMN source_ice_bytes integer NOT NULL DEFAULT 0 CHECK(source_ice_bytes BETWEEN 0 AND 262144),
 ADD COLUMN source_ice_complete boolean NOT NULL DEFAULT false,
 ADD COLUMN target_ice_count integer NOT NULL DEFAULT 0 CHECK(target_ice_count BETWEEN 0 AND 256),
 ADD COLUMN target_ice_bytes integer NOT NULL DEFAULT 0 CHECK(target_ice_bytes BETWEEN 0 AND 262144),
 ADD COLUMN target_ice_complete boolean NOT NULL DEFAULT false;
