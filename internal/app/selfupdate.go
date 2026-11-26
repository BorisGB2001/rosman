package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ExePath is the path of the running binary, captured at startup (before any
// self-update renames a new file over it).
var ExePath = func() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}()

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

const maxBinarySize = 200 << 20

var selfUpdMu sync.Mutex

func ghGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ROSMan")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub: HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

// SelfUpdate downloads the latest GitHub release binary for this OS/arch,
// verifies it (size, executable magic and — when the release publishes
// SHA256SUMS — its checksum) and atomically replaces the running binary,
// keeping the old one next to it as "<name>.prev". It returns the new version
// tag; the caller restarts the process to run it.
func (a *App) SelfUpdate(current string) (tag string, err error) {
	if !selfUpdMu.TryLock() {
		return "", errors.New("update already in progress")
	}
	defer selfUpdMu.Unlock()
	t := a.StartTask("self_update", "", 100)
	defer func() { t.Finish(err) }()

	if ExePath == "" {
		return "", errors.New("cannot locate the running binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Stage("upd_check", "")
	resp, err := ghGet(ctx, "https://api.github.com/repos/"+githubRepo+"/releases/latest")
	if err != nil {
		return "", err
	}
	var rel ghRelease
	err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("GitHub release: %w", err)
	}
	if rel.TagName == "" {
		return "", errors.New("GitHub: no release found")
	}
	if !verGreater(strings.TrimPrefix(rel.TagName, "v"), strings.TrimPrefix(current, "v")) {
		return "", fmt.Errorf("already up to date (%s)", rel.TagName)
	}
	want := fmt.Sprintf("rosman_%s_%s", runtime.GOOS, runtime.GOARCH)
	var bin, sums *ghAsset
	for i := range rel.Assets {
		switch rel.Assets[i].Name {
		case want:
			bin = &rel.Assets[i]
		case "SHA256SUMS":
			sums = &rel.Assets[i]
		}
	}
	if bin == nil {
		return "", fmt.Errorf("release %s has no build for %s/%s", rel.TagName, runtime.GOOS, runtime.GOARCH)
	}
	if bin.Size <= 0 || bin.Size > maxBinarySize {
		return "", fmt.Errorf("release asset has an implausible size (%d bytes)", bin.Size)
	}

	// Download next to the binary so the final rename is atomic (same filesystem).
	dir := filepath.Dir(ExePath)
	tmp, err := os.CreateTemp(dir, ".rosman-update-*")
	if err != nil {
		return "", fmt.Errorf("cannot write to %s (the service user needs write access to this directory): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		if err != nil {
			os.Remove(tmpName)
		}
	}()

	t.Stage("upd_download", rel.TagName)
	resp, err = ghGet(ctx, bin.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := sha256.New()
	var got int64
	buf := make([]byte, 256<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			got += int64(n)
			if got > bin.Size {
				return "", errors.New("download is larger than the release asset")
			}
			h.Write(buf[:n])
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				return "", werr
			}
			t.Advance(int(got * 90 / bin.Size))
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", fmt.Errorf("download: %w", rerr)
		}
	}
	if got != bin.Size {
		return "", fmt.Errorf("download incomplete: %d of %d bytes", got, bin.Size)
	}
	sum := hex.EncodeToString(h.Sum(nil))

	t.Stage("upd_verify", rel.TagName)
	t.Advance(92)
	if sums != nil {
		sresp, e := ghGet(ctx, sums.URL)
		if e != nil {
			return "", fmt.Errorf("SHA256SUMS: %w", e)
		}
		data, e := io.ReadAll(io.LimitReader(sresp.Body, 1<<20))
		sresp.Body.Close()
		if e != nil {
			return "", fmt.Errorf("SHA256SUMS: %w", e)
		}
		expect := ""
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 2 && strings.TrimPrefix(f[1], "*") == want {
				expect = strings.ToLower(f[0])
			}
		}
		if expect == "" {
			return "", errors.New("SHA256SUMS has no entry for " + want)
		}
		if expect != sum {
			return "", errors.New("checksum mismatch — download rejected")
		}
	}
	if err = tmp.Sync(); err != nil {
		return "", err
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	if !looksExecutable(tmpName) {
		err = errors.New("downloaded file is not an executable for this platform")
		return "", err
	}
	if err = os.Chmod(tmpName, 0o755); err != nil {
		return "", err
	}

	t.Stage("upd_install", rel.TagName)
	t.Advance(96)
	// Keep the running version for a manual rollback (best effort).
	prev := ExePath + ".prev"
	_ = os.Remove(prev)
	if e := os.Link(ExePath, prev); e != nil {
		_ = copyFile(ExePath, prev)
	}
	if err = os.Rename(tmpName, ExePath); err != nil {
		return "", fmt.Errorf("replace binary: %w", err)
	}
	t.Advance(100)
	return rel.TagName, nil
}

// looksExecutable checks the file's magic number against this platform's
// executable format, so an HTML error page or a wrong-OS build is never
// installed over the binary.
func looksExecutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	m := make([]byte, 4)
	if _, err := io.ReadFull(f, m); err != nil {
		return false
	}
	switch runtime.GOOS {
	case "linux":
		return bytes.Equal(m, []byte{0x7f, 'E', 'L', 'F'})
	case "darwin":
		return bytes.Equal(m, []byte{0xcf, 0xfa, 0xed, 0xfe}) || bytes.Equal(m, []byte{0xca, 0xfe, 0xba, 0xbe})
	}
	return true
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
