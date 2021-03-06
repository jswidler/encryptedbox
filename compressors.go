package encryptedbox

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
)

var (
	Zlib Compressor = ZlibCompression(zlib.BestCompression)
	Gzip Compressor = GzipCompression(gzip.BestCompression)
)

func GzipCompression(level int) Compressor {
	return gzipCompressor{level}
}

func ZlibCompression(level int) Compressor {
	return zlibCompressor{level}
}

type gzipCompressor struct {
	level int
}

func (z gzipCompressor) Compress(data []byte) ([]byte, error) {
	b := bytes.Buffer{}
	w, err := gzip.NewWriterLevel(&b, z.level)
	if err != nil {
		return nil, fmt.Errorf("failed to init gzip: %w", err)
	}
	_, err = w.Write(data)
	err2 := w.Close()
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	} else if err2 != nil {
		return nil, fmt.Errorf("compression failed: %w", err2)
	}
	return b.Bytes(), nil
}

func (z gzipCompressor) Decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	defer r.Close()
	out := bytes.Buffer{}
	_, err = io.Copy(&out, r)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	return out.Bytes(), nil
}

type zlibCompressor struct {
	level int
}

func (z zlibCompressor) Compress(data []byte) ([]byte, error) {
	b := bytes.Buffer{}
	w, err := zlib.NewWriterLevel(&b, z.level)
	if err != nil {
		return nil, fmt.Errorf("failed to init zlib: %w", err)
	}
	_, err = w.Write(data)
	err2 := w.Close()
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	} else if err2 != nil {
		return nil, fmt.Errorf("compression failed: %w", err2)
	}
	return b.Bytes(), nil
}

func (z zlibCompressor) Decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	defer r.Close()
	out := bytes.Buffer{}
	_, err = io.Copy(&out, r)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	return out.Bytes(), nil
}
