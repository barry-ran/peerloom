package relay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// NewDatabaseIssuer retains only an external encryption key, never a registry.
// An empty key permits deployments without relays; configuring/using a secret
// fails closed until a key is supplied.
func NewDatabaseIssuer(key []byte, ttl time.Duration, development bool) (*Issuer, error) {
	i, err := New(nil, ttl, development)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return i, nil
	}
	if len(key) != 32 {
		return nil, ErrConfiguration
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrConfiguration
	}
	i.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, ErrConfiguration
	}
	hash := sha256.Sum256(key)
	i.keyID = hex.EncodeToString(hash[:])
	return i, nil
}
func loadEncryptionKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, ErrConfiguration
	}
	return key, nil
}
func (i *Issuer) ValidateConfiguration(endpoint, secret string) error {
	if i == nil || i.aead == nil {
		return failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	if !validURL(endpoint, i.developmentLoopback) || !validSecret([]byte(secret)) {
		return failure("INVALID_RELAY_NODE", 422)
	}
	return nil
}
func (i *Issuer) ValidateEndpoint(endpoint string) error {
	if i == nil || !validURL(endpoint, i.developmentLoopback) {
		return failure("INVALID_RELAY_NODE", 422)
	}
	return nil
}
func validSecret(s []byte) bool {
	if len(s) < 32 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}
func secretAAD(nodeID, tenant, keyID string, version int64) []byte {
	b, _ := json.Marshal([]any{"peerloom-relay-secret-v1", nodeID, tenant, keyID, version})
	return b
}

// LockConfiguration serializes config selection with shared and tenant mutations.
// Call after LockTenant for tenant work; the offline shared path never takes a
// tenant lock. This prevents a partially observed multi-node snapshot.
func LockConfiguration(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(731004513)")
	if err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}

// StoreSecret appends a version; caller owns node/tenant and holds config lock.
func (i *Issuer) StoreSecret(ctx context.Context, tx pgx.Tx, nodeID, tenant, secret string, version int64) error {
	if i == nil || i.aead == nil {
		return failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	if !validSecret([]byte(secret)) || version < 1 {
		return failure("INVALID_RELAY_NODE", 422)
	}
	nonce := make([]byte, i.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	encrypted := i.aead.Seal(nil, nonce, []byte(secret), secretAAD(nodeID, tenant, i.keyID, version))
	_, err := tx.Exec(ctx, `INSERT INTO relay_secret_versions(node_id,version,tenant_id,key_id,nonce,ciphertext)
VALUES($1,$2,NULLIF($3,'')::uuid,$4,$5,$6)`, nodeID, version, tenant, i.keyID, nonce, encrypted)
	if err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}
func (i *Issuer) versionIssuer(ctx context.Context, tx pgx.Tx, nodeID, actorTenant, endpoint string, version int64) (*Issuer, Node, error) {
	if i == nil || i.aead == nil {
		return nil, Node{}, failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	var tenant, keyID string
	var nonce, encrypted []byte
	err := tx.QueryRow(ctx, `SELECT coalesce(tenant_id::text,''),key_id,nonce,ciphertext FROM relay_secret_versions
WHERE node_id=$1 AND version=$2 AND (tenant_id=$3 OR tenant_id IS NULL)`, nodeID, version, actorTenant).Scan(&tenant, &keyID, &nonce, &encrypted)
	if err != nil || keyID != i.keyID || len(nonce) != i.aead.NonceSize() {
		return nil, Node{}, failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	secret, err := i.aead.Open(nil, nonce, encrypted, secretAAD(nodeID, tenant, keyID, version))
	if err != nil {
		return nil, Node{}, failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	defer clear(secret)
	ref := "db-" + strconv.FormatInt(version, 10)
	issuer, err := New(map[string]SecretBinding{ref: {TenantID: tenant, Secret: secret, URLs: []string{endpoint}}}, i.ttl, i.developmentLoopback)
	if err != nil {
		return nil, Node{}, failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	return issuer, Node{TenantID: tenant, SecretRef: ref, URLs: []string{endpoint}}, nil
}
func (s *Service) snapshotNodes(ctx context.Context, tx pgx.Tx, tenant, session string) ([]selectedNode, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM relay_session_snapshots WHERE tenant_id=$1 AND session_id=$2)", tenant, session).Scan(&exists)
	if err != nil {
		return nil, failure("DATABASE_UNAVAILABLE", 503)
	}
	if !exists {
		if err = LockConfiguration(ctx, tx); err != nil {
			return nil, err
		}
		// The session row is already locked by AuthorizeICEInTx. A marker is written
		// even if there are zero relays, so later updates never attach to this session.
		_, err = tx.Exec(ctx, "INSERT INTO relay_session_snapshots(tenant_id,session_id) VALUES($1,$2)", tenant, session)
		if err != nil {
			return nil, failure("DATABASE_UNAVAILABLE", 503)
		}
		rows, err := tx.Query(ctx, `SELECT id::text,revision,endpoint,secret_version FROM relay_nodes
WHERE enabled AND (tenant_id=$1 OR tenant_id IS NULL)
ORDER BY (tenant_id IS NULL),created_at,id LIMIT 4 FOR SHARE`, tenant)
		if err != nil {
			return nil, failure("DATABASE_UNAVAILABLE", 503)
		}
		type entry struct {
			id, endpoint      string
			revision, version int64
		}
		var entries []entry
		for rows.Next() {
			var e entry
			if err = rows.Scan(&e.id, &e.revision, &e.endpoint, &e.version); err != nil {
				break
			}
			entries = append(entries, e)
		}
		rowsErr := rows.Err()
		rows.Close()
		if err != nil || rowsErr != nil {
			return nil, failure("DATABASE_UNAVAILABLE", 503)
		}
		for ordinal, e := range entries {
			if e.version == 0 {
				return nil, failure("RELAY_CONFIGURATION_REQUIRED", 503)
			}
			_, err = tx.Exec(ctx, `INSERT INTO relay_session_snapshot_nodes(tenant_id,session_id,ordinal,node_id,node_revision,endpoint,secret_version)
VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, session, ordinal, e.id, e.revision, e.endpoint, e.version)
			if err != nil {
				return nil, failure("DATABASE_UNAVAILABLE", 503)
			}
		}
	}
	rows, err := tx.Query(ctx, `SELECT node_id::text,node_revision,endpoint,secret_version FROM relay_session_snapshot_nodes
WHERE tenant_id=$1 AND session_id=$2 ORDER BY ordinal`, tenant, session)
	if err != nil {
		return nil, failure("DATABASE_UNAVAILABLE", 503)
	}
	var nodes []selectedNode
	for rows.Next() {
		var n selectedNode
		if err = rows.Scan(&n.ID, &n.Revision, &n.Endpoint, &n.SecretVersion); err != nil {
			break
		}
		nodes = append(nodes, n)
	}
	rowsErr := rows.Err()
	rows.Close()
	if err != nil || rowsErr != nil {
		return nil, failure("DATABASE_UNAVAILABLE", 503)
	}
	for j := range nodes {
		nodes[j].Issuer, nodes[j].Node, err = s.issuer.versionIssuer(ctx, tx, nodes[j].ID, tenant, nodes[j].Endpoint, nodes[j].SecretVersion)
		if err != nil {
			return nil, err
		}
	}
	return nodes, nil
}
