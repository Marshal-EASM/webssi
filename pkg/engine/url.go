package engine

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/urlscanner"
)

// ScanFileSystem scans a given file system.
func (e *Engine) ScanURL(ctx context.Context, c sources.URLConfig) (sources.JobProgressRef, error) {
	connection, err := json.Marshal(c)
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal URL connection")
		return sources.JobProgressRef{}, err
	}
	conn := anypb.Any{Value: connection}

	sourceName := "trufflehog - urlscan"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, sourcespb.SourceType_SOURCE_TYPE_STDIN)

	urlSource := &urlscanner.Source{}
	if err := urlSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, c.Concurrency); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, urlSource)
}
