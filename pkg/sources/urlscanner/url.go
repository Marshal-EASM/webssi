package urlscanner

import (
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_URL

type Source struct {
	name        string
	filename    string
	concurrency int
	sourceId    sources.SourceID
	jobId       sources.JobID
	verify      bool
	log         logr.Logger
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	var conn sourcespb.URLConfig
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}
	s.name = name
	s.concurrency = concurrency
	s.jobId = jobId
	s.sourceId = sourceId
	s.verify = verify
	s.filename = conn.GetFilename()
	s.log = aCtx.Logger()
	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	content, err := os.ReadFile(s.filename)
	if err != nil {
		return errors.WrapPrefix(err, "error opening URL list file", 0)
	}

	eg, _ := errgroup.WithContext(ctx)
	eg.SetLimit(s.concurrency)
	for _, line := range strings.Split(string(content), "\n") {
		target := strings.TrimSpace(line)
		if target == "" {
			continue
		}

		eg.Go(func() error {
			stdin, err := s.FetchURL(ctx, target)
			if err != nil {
				ctx.Logger().Error(err, "failed to fetch url", "url", target)
				return nil
			}
			defer stdin.Close()

			chunkSkel := &sources.Chunk{
				SourceType: s.Type(),
				SourceName: s.name,
				SourceID:   s.SourceID(),
				JobID:      s.JobID(),
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Url{
						Url: &source_metadatapb.URL{
							Link: target,
						},
					},
				},
				Verify: s.verify,
			}
			ctx.Logger().Info("scanning url for secrets", "url", target)
			return handlers.HandleFile(ctx, stdin, chunkSkel, sources.ChanReporter{Ch: chunksChan})
		})
	}
	return eg.Wait()
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	unit := sources.CommonSourceUnit{ID: s.filename}
	return reporter.UnitOk(ctx, unit)
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	ch := make(chan *sources.Chunk)
	go func() {
		defer close(ch)
		_ = s.Chunks(ctx, ch)
	}()
	for chunk := range ch {
		if chunk != nil {
			if err := reporter.ChunkOk(ctx, *chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Source) FetchURL(ctx context.Context, target string) (*os.File, error) {
	resp, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.WrapPrefix(err, "error creating HTTP request", 0)
	}

	client := &http.Client{}
	response, err := client.Do(resp)
	if err != nil {
		return nil, errors.WrapPrefix(err, "error performing HTTP request", 0)
	}
	defer response.Body.Close()

	f, err := os.CreateTemp("", "")
	if err != nil {
		return nil, errors.WrapPrefix(err, "error creating temp file", 0)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.WrapPrefix(err, "error reading HTTP response body", 0)
	}

	f.Write(body)
	return f, nil
}
