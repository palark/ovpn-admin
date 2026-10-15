package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestCacheControlWrapper(t *testing.T) {
	files := fstest.MapFS{
		"index.html":         {Data: []byte("<div id=app></div>")},
		"dist/bundle.min.js": {Data: []byte("console.log(1)")},
	}
	handler := CacheControlWrapper(http.FileServer(http.FS(files)), files)

	for _, path := range []string{"/", "/dist/bundle.min.js"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q, want no-cache", path, got)
		}
		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("GET %s: no ETag", path)
		}

		// revalidation of an unchanged file
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("If-None-Match", etag)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Errorf("GET %s with If-None-Match = %d, want 304", path, rec.Code)
		}
	}

	// a changed file gets a different ETag
	other := fstest.MapFS{"index.html": {Data: []byte("<div id=app>v2</div>")}}
	if staticETags(files)["index.html"] == staticETags(other)["index.html"] {
		t.Error("different content has the same ETag")
	}
}

func TestStaticFilePath(t *testing.T) {
	tests := map[string]string{
		"/":                   "index.html",
		"":                    "index.html",
		"/dist/bundle.min.js": "dist/bundle.min.js",
		"/dist/":              "dist/index.html",
		"/../index.html":      "index.html",
	}
	for in, want := range tests {
		if got := staticFilePath(in); got != want {
			t.Errorf("staticFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
