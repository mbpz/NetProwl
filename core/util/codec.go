package util

import (
    "bytes"
    "compress/gzip"
    "encoding/base64"
    "io"
)

// GzipEncode compresses data and returns base64-encoded string.
func GzipEncode(data []byte) (string, error) {
    var buf bytes.Buffer
    writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
    if err != nil {
        return "", err
    }
    if _, err := writer.Write(data); err != nil {
        return "", err
    }
    if err := writer.Close(); err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// GzipDecode decodes base64 string and decompresses.
func GzipDecode(encoded string) ([]byte, error) {
    data, err := base64.StdEncoding.DecodeString(encoded)
    if err != nil {
        return nil, err
    }
    reader, err := gzip.NewReader(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }
    defer reader.Close()
    return io.ReadAll(reader)
}
