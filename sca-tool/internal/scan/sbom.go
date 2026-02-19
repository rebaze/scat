package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
)

// CreateSBOM uses the Syft library to generate a CycloneDX JSON SBOM.
func CreateSBOM(sourceDir, outPath string, verbose bool) error {
	ctx := context.Background()

	src, err := syft.GetSource(ctx, "dir:"+sourceDir, syft.DefaultGetSourceConfig())
	if err != nil {
		return fmt.Errorf("creating source from %s: %w", sourceDir, err)
	}

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return fmt.Errorf("creating SBOM: %w", err)
	}

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{
		Version: "1.6",
		Pretty:  true,
	})
	if err != nil {
		return fmt.Errorf("creating CycloneDX encoder: %w", err)
	}

	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *s); err != nil {
		return fmt.Errorf("encoding SBOM: %w", err)
	}

	return os.WriteFile(outPath, buf.Bytes(), 0o644)
}
