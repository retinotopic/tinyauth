package safectx

import "context"

type ctxKey string

func SetContext(ctx context.Context, key string, value any) context.Context {
	return context.WithValue(ctx, ctxKey(key), value)
}
func GetContextString(ctx context.Context, key string) (string, bool) {
	val, ok := ctx.Value(ctxKey(key)).(string)
	return val, ok
}
