package signaling

import (
	"context"
	"errors"
	"strconv"

	"github.com/barry-ran/peerloom/src/device-server/internal/presence"
	"github.com/coder/websocket"
)

// Zero disables a deployment policy; frame sizes and bounded queues remain enforced.
type Options struct {
	MaxConnections  int
	FramesPerSecond int
}

func LoadOptions(getenv func(string) string) (Options, error) {
	var result Options
	for _, value := range []struct {
		name   string
		target *int
	}{
		{"SIGNAL_MAX_CONNECTIONS", &result.MaxConnections},
		{"SIGNAL_FRAMES_PER_SECOND", &result.FramesPerSecond},
	} {
		if raw := getenv(value.name); raw != "" {
			number, err := strconv.Atoi(raw)
			if err != nil || number < 0 {
				return Options{}, errors.New("invalid signaling capacity policy")
			}
			*value.target = number
		}
	}
	return result, nil
}
func NewWithOptions(auth Authenticator, store presence.Store, dispatch Dispatch, options Options) (*Server, error) {
	if options.MaxConnections < 0 || options.FramesPerSecond < 0 {
		return nil, errors.New("invalid signaling capacity policy")
	}
	return &Server{auth: auth, presence: store, dispatch: dispatch, options: options, peers: make(map[string]*peer), connections: make(map[*websocket.Conn]context.CancelFunc)}, nil
}
