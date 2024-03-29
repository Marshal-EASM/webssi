package openai

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strconv"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

// The magic string T3BlbkFJ is the base64-encoded string: OpenAI
var keyPat = regexp.MustCompile(`\b(sk-[[:alnum:]]{20}T3BlbkFJ[[:alnum:]]{20})\b`)

// TODO: Add secret context?? Information about access, ownership etc
type orgResponse struct {
	Data []organization `json:"data"`
}

type organization struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	User        string `json:"name"`
	Description string `json:"description"`
	Personal    bool   `json:"personal"`
	Default     bool   `json:"is_default"`
	Role        string `json:"role"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"T3BlbkFJ"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// First match is entire regex, second is the first group.
		if len(match) != 2 {
			continue
		}

		token := match[1]

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenAI,
			Redacted:     token[:3] + "..." + token[47:],
			Raw:          []byte(token),
		}

		if verify {
			client := common.SaneHttpClient()
			// Undocumented API
			// https://api.openai.com/v1/organizations
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.openai.com/v1/organizations", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json; charset=utf-8")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
			res, err := client.Do(req)
			if err == nil {
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var orgs orgResponse
					err = json.NewDecoder(res.Body).Decode(&orgs)
					res.Body.Close()
					if err == nil {
						s1.Verified = true
						org := orgs.Data[0]
						s1.ExtraData = map[string]string{
							"id":          org.ID,
							"title":       org.Title,
							"user":        org.User,
							"description": org.Description,
							"role":        org.Role,
							"is_personal": strconv.FormatBool(org.Personal),
							"is_default":  strconv.FormatBool(org.Default),
							"total_orgs":  fmt.Sprintf("%d", len(orgs.Data)),
						}
					}
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenAI
}
