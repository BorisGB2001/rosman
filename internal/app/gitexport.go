package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// gitSafe keeps device-name-derived file names tame.
var gitSafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (a *App) gitDir() string {
	if d := a.setting("git_dir"); d != "" {
		return d
	}
	return filepath.Join(a.Cfg.DataDir, "config-git")
}

// GitExportEnabled reports whether scheduled git export is turned on.
func (a *App) GitExportEnabled() bool { return a.setting("git_enabled") == "on" }

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=ROSMan", "GIT_AUTHOR_EMAIL=rosman@localhost",
		"GIT_COMMITTER_NAME=ROSMan", "GIT_COMMITTER_EMAIL=rosman@localhost",
		"GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// GitExport writes every device's latest /export to files in the git working
// tree and commits any changes (pushing when a remote is configured). It is a
// pure serialization of already-stored exports — it does not touch devices.
func (a *App) GitExport() (string, error) {
	dir := a.gitDir()
	branch := a.setting("git_branch")
	if branch == "" {
		branch = "main"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if out, e := git(dir, "init", "-q", "-b", branch); e != nil {
			return "", fmt.Errorf("git init: %v (%s)", e, out)
		}
	}

	devs, err := a.Store.Devices()
	if err != nil {
		return "", err
	}
	written := 0
	for _, d := range devs {
		cfg, err := a.Store.LatestConfig(d.ID, "export")
		if err != nil || strings.TrimSpace(cfg.Content) == "" {
			continue
		}
		name := gitSafe.ReplaceAllString(d.Name, "_")
		if name == "" {
			name = fmt.Sprintf("device-%d", d.ID)
		}
		fp := filepath.Join(dir, name+".rsc")
		if err := os.WriteFile(fp, []byte(cfg.Content+"\n"), 0o600); err == nil {
			written++
		}
	}

	if _, err := git(dir, "add", "-A"); err != nil {
		return "", fmt.Errorf("git add failed")
	}
	// Nothing staged → nothing to do.
	if _, err := git(dir, "diff", "--cached", "--quiet"); err == nil {
		a.setGitLast("no changes")
		return "no changes", nil
	}
	msg := "rosman config export " + time.Now().Format("2006-01-02 15:04:05")
	if out, err := git(dir, "commit", "-q", "-m", msg); err != nil {
		return "", fmt.Errorf("git commit: %v (%s)", err, out)
	}
	result := fmt.Sprintf("committed %d file(s)", written)
	if remote := a.setting("git_remote"); remote != "" {
		_, _ = git(dir, "remote", "remove", "origin")
		if out, err := git(dir, "remote", "add", "origin", remote); err != nil {
			result += " (remote add: " + out + ")"
		} else if out, err := git(dir, "push", "-q", "-u", "origin", branch); err != nil {
			result += " (push failed: " + out + ")"
		} else {
			result += " + pushed"
		}
	}
	a.setGitLast(result)
	return result, nil
}

func (a *App) setGitLast(s string) {
	_ = a.Store.SetSetting("git_last", time.Now().Format("2006-01-02 15:04")+" — "+s)
}

// GitExportIfEnabled runs GitExport only when the feature is on (used by the
// scheduler after a backup cycle).
func (a *App) GitExportIfEnabled() {
	if a.GitExportEnabled() {
		if _, err := a.GitExport(); err != nil {
			a.setGitLast("error: " + err.Error())
		}
	}
}
