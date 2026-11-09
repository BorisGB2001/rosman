package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Full-application backup: a password-encrypted archive of the whole data dir
// (a consistent DB snapshot + secret.key + TLS + model/reference/config files),
// so the entire ROSMan instance can be restored on another host.
//
// On-disk blob layout: magic "RBK1" | salt(16) | nonce(12) | AES-256-GCM(tar.gz).
// The key is scrypt(password, salt). A wrong password fails the GCM auth tag.

const (
	backupMagic   = "RBK1"
	restoreFlag   = "RESTORE_PENDING"
	restoreStage  = "restore-staging"
	scryptN       = 1 << 15
	scryptR       = 8
	scryptP       = 1
	backupKeyLen  = 32
	backupSaltLen = 16
)

func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, backupKeyLen)
}

func encryptBlob(plain []byte, password string) ([]byte, error) {
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := []byte(backupMagic)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, []byte(backupMagic))
	return out, nil
}

func decryptBlob(blob []byte, password string) ([]byte, error) {
	hdr := len(backupMagic) + backupSaltLen + 12
	if len(blob) < hdr || string(blob[:len(backupMagic)]) != backupMagic {
		return nil, fmt.Errorf("не похоже на бэкап ROSMan")
	}
	salt := blob[len(backupMagic) : len(backupMagic)+backupSaltLen]
	nonce := blob[len(backupMagic)+backupSaltLen : hdr]
	ct := blob[hdr:]
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(backupMagic))
	if err != nil {
		return nil, fmt.Errorf("неверный пароль или повреждённый файл")
	}
	return plain, nil
}

// archivePaths lists the data-dir-relative files to include, substituting a
// consistent DB snapshot for the live rosman.db and skipping its WAL/SHM and any
// in-progress restore artifacts.
func (a *App) BackupFilename() string {
	return "rosman-backup-" + time.Now().Format("2006-01-02-1504") + ".rbk"
}

// ExportBackup produces the encrypted full-backup blob.
func (a *App) ExportBackup(password string) ([]byte, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("нужен пароль")
	}
	dir := a.Cfg.DataDir
	// Consistent DB snapshot via VACUUM INTO (safe while the DB is live).
	snap := filepath.Join(dir, "backup-snapshot.db")
	_ = os.Remove(snap)
	if err := a.Store.Backup(snap); err != nil {
		return nil, fmt.Errorf("снимок БД: %w", err)
	}
	defer os.Remove(snap)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addFile := func(nameInTar, srcPath string) error {
		info, err := os.Stat(srcPath)
		if err != nil {
			return err
		}
		f, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer f.Close()
		hdr := &tar.Header{Name: nameInTar, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return err
	}

	// The DB snapshot is stored as rosman.db inside the archive.
	if err := addFile("rosman.db", snap); err != nil {
		return nil, err
	}
	// Everything else under the data dir, except the live DB files and restore
	// artifacts, preserving relative paths (secret.key, tls.*, models/, …).
	skip := map[string]bool{"rosman.db": true, "rosman.db-wal": true, "rosman.db-shm": true,
		"backup-snapshot.db": true, restoreFlag: true}
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		if top == restoreStage {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		if skip[rel] {
			return nil
		}
		return addFile(rel, p)
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return encryptBlob(buf.Bytes(), password)
}

// StageRestore decrypts and validates a backup blob, extracts it into a staging
// directory and sets the RESTORE_PENDING flag. The restore is applied on the
// next startup (ApplyPendingRestore), before the DB and key are opened — so a
// running instance is never corrupted mid-flight. Returns the number of files.
func (a *App) StageRestore(blob []byte, password string) (int, error) {
	plain, err := decryptBlob(blob, password)
	if err != nil {
		return 0, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return 0, fmt.Errorf("неверный пароль или повреждённый файл")
	}
	tr := tar.NewReader(gz)
	stage := filepath.Join(a.Cfg.DataDir, restoreStage)
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return 0, err
	}
	n, hasDB := 0, false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = os.RemoveAll(stage)
			return 0, err
		}
		// Guard against path traversal in a crafted archive.
		clean := filepath.Clean(hdr.Name)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
			continue
		}
		dst := filepath.Join(stage, clean)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			_ = os.RemoveAll(stage)
			return 0, err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = os.RemoveAll(stage)
			return 0, err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			_ = os.RemoveAll(stage)
			return 0, err
		}
		out.Close()
		if clean == "rosman.db" {
			hasDB = true
		}
		n++
	}
	if !hasDB {
		_ = os.RemoveAll(stage)
		return 0, fmt.Errorf("в архиве нет rosman.db — это не бэкап ROSMan")
	}
	// Flag it; the next startup moves staging into place.
	if err := os.WriteFile(filepath.Join(a.Cfg.DataDir, restoreFlag), []byte(time.Now().Format(time.RFC3339)), 0o600); err != nil {
		return 0, err
	}
	return n, nil
}

// ApplyPendingRestore, called at startup before the DB/key are opened, applies a
// staged restore: it replaces the live DB and key (and all other staged files)
// with the backup's, drops the stale WAL/SHM, and clears the staging + flag.
func ApplyPendingRestore(dataDir string) (applied bool, err error) {
	flag := filepath.Join(dataDir, restoreFlag)
	if _, e := os.Stat(flag); e != nil {
		return false, nil
	}
	stage := filepath.Join(dataDir, restoreStage)
	// Drop the live DB side-files so the restored DB opens clean.
	_ = os.Remove(filepath.Join(dataDir, "rosman.db-wal"))
	_ = os.Remove(filepath.Join(dataDir, "rosman.db-shm"))
	err = filepath.Walk(stage, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(stage, p)
		if e != nil {
			return e
		}
		dst := filepath.Join(dataDir, rel)
		if e := os.MkdirAll(filepath.Dir(dst), 0o700); e != nil {
			return e
		}
		in, e := os.Open(p)
		if e != nil {
			return e
		}
		defer in.Close()
		out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if e != nil {
			return e
		}
		if _, e := io.Copy(out, in); e != nil {
			out.Close()
			return e
		}
		return out.Close()
	})
	if err != nil {
		return false, fmt.Errorf("apply restore: %w", err)
	}
	_ = os.RemoveAll(stage)
	_ = os.Remove(flag)
	return true, nil
}
