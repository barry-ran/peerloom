// Package presence implements rebuildable, fenced online ownership in Redis.
package presence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const LeaseTTL = 45 * time.Second

var ErrFenced = errors.New("presence ownership lost")

type Lease struct {
	Generation int64  `json:"connection_generation"`
	Token      string `json:"fencing_token"`
}

type Store interface {
	Claim(context.Context, string, string) (Lease, error)
	Renew(context.Context, string, string, Lease) error
	Release(context.Context, string, string, Lease) error
}

type Redis struct{ client redis.UniversalClient }

func NewRedis(client redis.UniversalClient) *Redis { return &Redis{client: client} }
func keys(tenant, device string) (string, string) {
	key := "peerloom:presence:{" + tenant + ":" + device + "}"
	return key, key + ":generation"
}

// The random fence remains unique even after Redis loss or counter expiration.
func (s *Redis) Claim(ctx context.Context, tenant, device string) (Lease, error) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Lease{}, err
	}
	lease := Lease{Token: hex.EncodeToString(entropy[:])}
	key, counter := keys(tenant, device)
	generation, err := s.client.Eval(ctx, `local old=tonumber(redis.call('GET',KEYS[2]) or '0'); if not old or old<0 or old>=9007199254740991 then return redis.error_reply('generation exhausted') end; local n=redis.call('INCR',KEYS[2]); redis.call('PEXPIRE',KEYS[2],604800000); redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[2]); return n`, []string{key, counter}, lease.Token, LeaseTTL.Milliseconds()).Int64()
	if err != nil {
		return Lease{}, errors.New("presence unavailable")
	}
	if generation < 1 || generation > 9007199254740991 {
		return Lease{}, errors.New("presence generation exhausted")
	}
	lease.Generation = generation
	return lease, nil
}
func (s *Redis) Renew(ctx context.Context, tenant, device string, lease Lease) error {
	key, _ := keys(tenant, device)
	ok, err := s.client.Eval(ctx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) else return 0 end`, []string{key}, lease.Token, LeaseTTL.Milliseconds()).Int()
	if err != nil {
		return errors.New("presence unavailable")
	}
	if ok != 1 {
		return ErrFenced
	}
	return nil
}
func (s *Redis) Release(ctx context.Context, tenant, device string, lease Lease) error {
	key, _ := keys(tenant, device)
	_, err := s.client.Eval(ctx, `if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`, []string{key}, lease.Token).Result()
	if err != nil {
		return errors.New("presence unavailable")
	}
	return nil
}

// Online never treats an unavailable cache as evidence of an online device.
func (s *Redis) Online(ctx context.Context, tenant, device string) (bool, error) {
	key, _ := keys(tenant, device)
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, errors.New("presence unavailable")
	}
	return n == 1, nil
}
