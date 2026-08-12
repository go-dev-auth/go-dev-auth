package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var defaultHTTPClient = http.DefaultClient

// getJSONList performs an authenticated GET returning a JSON array.
func getJSONList(ctx context.Context, client *http.Client, url, accessToken string) ([]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("providers: %s returned %d", url, res.StatusCode)
	}
	var out []any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
