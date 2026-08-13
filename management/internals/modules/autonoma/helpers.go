package autonoma

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/autonoma-ai/sdk/sdks/go/autonoma"

	"github.com/netbirdio/netbird/shared/management/status"
)

func writeJSONBody(w io.Writer, body map[string]any) error {
	return json.NewEncoder(w).Encode(body)
}

// defineFactory is a thin wrapper that keeps the registry table readable: every
// entry names its input struct, its create function and its teardown.
func defineFactory[I any](
	create func(in *I, ctx autonoma.FactoryContext) (map[string]any, error),
	teardown func(record map[string]any, ctx autonoma.FactoryContext) error,
) autonoma.FactoryDefinition {
	def := autonoma.FactoryDefinition{
		InputStruct: reflect.TypeOf(*new(I)),
		Create: func(input interface{}, ctx autonoma.FactoryContext) (map[string]any, error) {
			in, ok := input.(*I)
			if !ok {
				return nil, errors.New("unexpected input type")
			}
			return create(in, ctx)
		},
	}
	if teardown != nil {
		def.Teardown = func(record interface{}, ctx autonoma.FactoryContext) error {
			rec, ok := record.(map[string]any)
			if !ok {
				return errors.New("unexpected teardown record type")
			}
			return teardown(rec, ctx)
		}
	}
	return def
}

// recordString reads a string field off a stored ref record. Teardown receives
// whatever create returned, round-tripped through JSON.
func recordString(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

// ignoreNotFound swallows the "already gone" error so teardown is idempotent:
// the account delete that runs last removes rows some per-record teardowns have
// already taken, and a repeated "down" must not fail.
func ignoreNotFound(err error) error {
	if err == nil {
		return nil
	}
	var sErr *status.Error
	if errors.As(err, &sErr) && sErr.Type() == status.NotFound {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		return nil
	}
	return err
}

// fromNow turns a recipe-supplied offset into an instant. Every seeded value the
// application compares against the current time is expressed as an offset so it
// still lands on the intended side of "now" months after the recipe was written.
func fromNow(minutes int64) time.Time {
	return time.Now().UTC().Add(time.Duration(minutes) * time.Minute)
}

// minutesToDuration converts a recipe-supplied offset in minutes to a Duration.
func minutesToDuration(minutes int64) time.Duration {
	return time.Duration(minutes) * time.Minute
}
