package diagnose

import (
	"context"
	"errors"
	"time"

	"SynoMailPlusSetupAssistant/internal/core"
)

// RelayStatusSource is satisfied by the existing mail/relay.Service.
// Do not call Credentials or TestUpstream from diagnostics.
type RelayStatusSource interface {
	Status() core.ServiceStatus
}

// WithRelay adds the running service's observations to a detector adapter.
// The base detector must still establish whether MailPlus uses Home Keeper.
// It reads only Status and KV.Get, never relay credentials or message data.
func WithRelay(base StateSource, status RelayStatusSource) StateSource {
	return relayStateSource{base: base, status: status}
}

type relayStateSource struct {
	base   StateSource
	status RelayStatusSource
}

func (s relayStateSource) Snapshot(ctx context.Context, env core.Env) (State, error) {
	if s.base == nil {
		return State{}, errors.New("mail diagnostic detector required")
	}
	state, err := s.base.Snapshot(ctx, env)
	if err != nil {
		return State{}, err
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	if s.status != nil {
		status := s.status.Status()
		state.Relay.Running = &status.Running
		// In-memory success wins over stale persistent state after a write
		// failure following an already committed upstream delivery.
		if raw := status.Info["lastSuccess"]; raw != "" {
			state.Relay.LastSuccess, _ = time.Parse(time.RFC3339Nano, raw)
			return state, nil
		}
	}
	if env.KV != nil {
		var last time.Time
		found, err := env.KV.Get(ctx, "mail.relay", "lastSuccess", &last)
		if err != nil || !found {
			state.Relay.LastSuccess = time.Time{}
		} else {
			state.Relay.LastSuccess = last
		}
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	return state, nil
}
