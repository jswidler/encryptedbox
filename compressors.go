package encryptedbox

import (
	"bytes"
	"compress/zlib"
	"io"
)

var Zlib Compressor = ZlibCompression(zlib.BestCompression)

func ZlibCompression(level int) Compressor {
	return zlibCompressor{level}
}

type zlibCompressor struct {
	level int
}

func (z zlibCompressor) Compress(data []byte) ([]byte, error) {
	b := bytes.Buffer{}
	w, err := zlib.NewWriterLevel(&b, z.level)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(data)
	err2 := w.Close()
	if err != nil {
		return nil, err
	} else if err2 != nil {
		return nil, err2
	}
	return b.Bytes(), nil
}

func (z zlibCompressor) Decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := bytes.Buffer{}
	_, err = io.Copy(&out, r)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
