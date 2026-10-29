package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// embedder talks to an OpenAI-compatible /embeddings endpoint. It is entirely
// optional: without REASONIX_SECKB_EMBED_URL the KB is pure BM25 and fully
// offline. The rerank step is the only integration point, so a vector store
// (Milvus, Chroma, ...) can replace it later without changing the tool API.
type embedder struct {
	url    string
	model  string
	apiKey string
	client *http.Client
}

func embedderFromEnv() *embedder {
	url := strings.TrimSpace(os.Getenv("REASONIX_SECKB_EMBED_URL"))
	if url == "" {
		return nil
	}
	model := strings.TrimSpace(os.Getenv("REASONIX_SECKB_EMBED_MODEL"))
	if model == "" {
		model = "text-embedding-3-small"
	}
	return &embedder{
		url:    url,
		model:  model,
		apiKey: os.Getenv("REASONIX_SECKB_EMBED_API_KEY"),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
}

func (e *embedder) embed(ctx context.Context, texts []string) ([][]float64, error) {
	body, err := json.Marshal(embedRequest{Model: e.model, Input: texts})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embeddings endpoint %s: %s", resp.Status, truncate(string(raw), 200))
	}
	var parsed embedResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse embeddings response: %w", err)
	}
	if len(parsed.Data) != len(texts) {
		return nil, fmt.Errorf("embeddings endpoint returned %d vectors for %d inputs", len(parsed.Data), len(texts))
	}
	out := make([][]float64, len(texts))
	for i, d := range parsed.Data {
		out[i] = d.Embedding
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// vector blob encoding: little-endian float64 sequence.

func encodeVector(v []float64) []byte {
	buf := make([]byte, 8*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint64(buf[8*i:], math.Float64bits(f))
	}
	return buf
}

func decodeVector(buf []byte) []float64 {
	v := make([]float64, len(buf)/8)
	for i := range v {
		v[i] = math.Float64frombits(binary.LittleEndian.Uint64(buf[8*i:]))
	}
	return v
}

func cosine(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

// vector cache in SQLite

func (s *store) getVector(docID int64, model string) ([]float64, bool) {
	var blob []byte
	err := s.db.QueryRow(`SELECT vector FROM embeddings WHERE doc_id = ? AND model = ?`, docID, model).Scan(&blob)
	if err != nil {
		return nil, false
	}
	return decodeVector(blob), true
}

func (s *store) putVector(docID int64, model string, v []float64) error {
	_, err := s.db.Exec(`INSERT INTO embeddings(doc_id, model, vector) VALUES(?, ?, ?)
		ON CONFLICT(doc_id) DO UPDATE SET model = excluded.model, vector = excluded.vector`,
		docID, model, encodeVector(v))
	return err
}

// searchHybrid reranks BM25 candidates with semantic similarity:
// final = 0.5 * normalized BM25 + 0.5 * ((cosine+1)/2). Any embedding error
// degrades gracefully to the pure BM25 order.
func (srv *server) searchHybrid(query, collection string, topK int) ([]hit, string, error) {
	candidates := topK * 3
	if candidates < 12 {
		candidates = 12
	}
	hits, err := srv.st.searchBM25(query, collection, candidates)
	if err != nil || len(hits) == 0 || srv.embed == nil {
		return hits, "bm25", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	maxBM25 := hits[0].bm25
	missingIdx := []int{}
	vecs := make([][]float64, len(hits))
	for i, h := range hits {
		if v, ok := srv.st.getVector(h.doc.ID, srv.embed.model); ok {
			vecs[i] = v
		} else {
			missingIdx = append(missingIdx, i)
		}
	}
	if len(missingIdx) > 0 {
		texts := make([]string, len(missingIdx))
		for j, i := range missingIdx {
			texts[j] = hits[i].doc.Title + "\n" + hits[i].doc.Body
		}
		computed, err := srv.embed.embed(ctx, texts)
		if err != nil {
			log.Printf("embedding rerank unavailable, using bm25: %v", err)
			return trimHits(hits, topK), "bm25", nil
		}
		for j, i := range missingIdx {
			vecs[i] = computed[j]
			if err := srv.st.putVector(hits[i].doc.ID, srv.embed.model, computed[j]); err != nil {
				log.Printf("cache embedding for doc %d: %v", hits[i].doc.ID, err)
			}
		}
	}
	queryVec, err := srv.embed.embed(ctx, []string{query})
	if err != nil {
		log.Printf("query embedding unavailable, using bm25: %v", err)
		return trimHits(hits, topK), "bm25", nil
	}
	for i := range hits {
		normBM25 := 0.0
		if maxBM25 > 0 {
			normBM25 = hits[i].bm25 / maxBM25
		}
		sem := (cosine(queryVec[0], vecs[i]) + 1) / 2
		hits[i].final = 0.5*normBM25 + 0.5*sem
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].final > hits[j].final })
	return trimHits(hits, topK), "hybrid", nil
}

func trimHits(hits []hit, topK int) []hit {
	if topK > 0 && len(hits) > topK {
		return hits[:topK]
	}
	return hits
}
