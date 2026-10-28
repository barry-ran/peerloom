package signaling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

// AuthorizationDispatch never accepts a tenant, actor, grant or lease from a client.
func AuthorizationDispatch(service *authorization.Service) Dispatch {
	return func(ctx context.Context, actor identity.Device, e Envelope) ([]Delivery, error) {
		var session authorization.Session
		var err error
		switch e.Type {
		case "session.request":
			var request struct {
				TargetDeviceID string `json:"target_device_id"`
			}
			if e.SessionID != "" || decodePayload(e.Payload, &request) != nil || !uuidPattern.MatchString(request.TargetDeviceID) {
				return closedDeliveries(session, e.ID), errors.New("invalid request")
			}
			session, err = service.Request(ctx, actor, request.TargetDeviceID, e.ID)
		case "session.accept", "session.reject":
			if !validSession(e) || !EmptyPayload(e) {
				return closedDeliveries(session, e.ID), errors.New("invalid response")
			}
			session, err = service.Respond(ctx, actor, e.SessionID, e.Type == "session.accept")
		case "session.renew":
			if !validSession(e) || !EmptyPayload(e) {
				return closedDeliveries(session, e.ID), errors.New("invalid renewal")
			}
			session, err = service.Renew(ctx, actor, e.SessionID)
		case "session.connected":
			if !validSession(e) || !EmptyPayload(e) {
				return closedDeliveries(session, e.ID), errors.New("invalid connected")
			}
			session, err = service.MarkConnected(ctx, actor, e.SessionID)
		case "session.terminate":
			if !validSession(e) || !EmptyPayload(e) {
				return closedDeliveries(session, e.ID), errors.New("invalid termination")
			}
			session, err = service.Close(ctx, actor, e.SessionID, "peer_terminated")
		case "session.offer", "session.answer":
			if !validSession(e) || e.Negotiation != 1 {
				return closedDeliveries(session, e.ID), errors.New("unsupported negotiation")
			}
			var description struct {
				SDP string `json:"sdp"`
			}
			if decodePayload(e.Payload, &description) != nil || len(description.SDP) == 0 || len(description.SDP) > 65536 {
				return closedDeliveries(session, e.ID), errors.New("invalid description")
			}
			session, err = service.AuthorizeDescription(ctx, actor, e.SessionID, e.Type)
			if err != nil {
				return closedDeliveries(session, e.ID), err
			}
			target := session.TargetDeviceID
			if actor.ID == target {
				target = session.SourceDeviceID
			}
			return []Delivery{{TenantID: actor.TenantID, DeviceID: target, Message: Envelope{Type: e.Type, SessionID: session.ID, Negotiation: 1, RequestID: e.ID, Payload: e.Payload}}}, nil
		case "sync.request":
			if !validSession(e) || !EmptyPayload(e) {
				return closedDeliveries(session, e.ID), errors.New("invalid sync")
			}
			session, err = service.Get(ctx, actor, e.SessionID)
			if err != nil {
				return closedDeliveries(session, e.ID), err
			}
			payload, _ := json.Marshal(session)
			return []Delivery{{TenantID: actor.TenantID, DeviceID: actor.ID, Message: Envelope{Type: "sync.snapshot", SessionID: session.ID, RequestID: e.ID, Payload: payload}}}, nil
		default:
			return closedDeliveries(session, e.ID), errors.New("unsupported message")
		}
		if err != nil {
			return closedDeliveries(session, e.ID), err
		}
		kind := "session.updated"
		if session.State == "authorizing" {
			kind = "session.pending"
		}
		if session.State == "closed" {
			kind = "session.terminated"
		}
		payload, _ := json.Marshal(session)
		message := Envelope{Type: kind, SessionID: session.ID, RequestID: e.ID, Payload: payload}
		return []Delivery{{TenantID: session.TenantID, DeviceID: session.SourceDeviceID, Message: message}, {TenantID: session.TenantID, DeviceID: session.TargetDeviceID, Message: message}}, nil
	}
}
func validSession(e Envelope) bool { return uuidPattern.MatchString(e.SessionID) }
func decodePayload(data []byte, destination any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(destination)
}

// NotifySession broadcasts a server-authoritative state change to current peers.
// It does not persist signaling messages; clients must reconcile via sync.
func (s *Server) NotifySession(session authorization.Session) {
	payload, _ := json.Marshal(session)
	kind := "session.updated"
	if session.State == "closed" {
		kind = "session.terminated"
	}
	message := Envelope{Type: kind, SessionID: session.ID, Payload: payload}
	s.deliver(session.TenantID, session.SourceDeviceID, message)
	s.deliver(session.TenantID, session.TargetDeviceID, message)
}

func failureCode(err error) string {
	var failure *authorization.Error
	if errors.As(err, &failure) {
		return failure.Code
	}
	return "INVALID_INPUT"
}

func closedDeliveries(session authorization.Session, requestID string) []Delivery {
	if session.State != "closed" || session.ID == "" {
		return nil
	}
	payload, _ := json.Marshal(session)
	message := Envelope{Type: "session.terminated", SessionID: session.ID, RequestID: requestID, Payload: payload}
	return []Delivery{{TenantID: session.TenantID, DeviceID: session.SourceDeviceID, Message: message}, {TenantID: session.TenantID, DeviceID: session.TargetDeviceID, Message: message}}
}
