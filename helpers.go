package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func parseDate(layout, datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Errorln(err)
	}
	return t
}

func parseDateToString(layout, datetime, format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout, datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

// runCommand runs a program directly, without a shell, so arguments are never
// interpreted. dir is the working directory ("" = current), stdin is fed to the
// program when not empty. The combined output is logged at debug level.
func runCommand(dir, stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	out, err := cmd.CombinedOutput()
	cmdLine := strings.Join(append([]string{name}, redactArgs(args)...), " ")
	if err != nil {
		log.Debugf("%s: %v: %s", cmdLine, err, out)
		return string(out), fmt.Errorf("%s: %w", cmdLine, err)
	}
	log.Debugf("%s: %s", cmdLine, out)

	return string(out), nil
}

// redactArgs hides values of --password arguments ("--password VALUE" and "--password=VALUE") in logs
func redactArgs(args []string) []string {
	redacted := make([]string, len(args))
	for i, arg := range args {
		switch {
		case i > 0 && args[i-1] == "--password":
			arg = "******"
		case strings.HasPrefix(arg, "--password="):
			arg = "--password=******"
		}
		redacted[i] = arg
	}
	return redacted
}

func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Errorf("fExist: %s", err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Warning(err)
		return ""
	}

	return string(content)
}

func fWrite(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func fDelete(path string) error {
	return os.Remove(path)
}

func fCopy(src, dst string) error {
	sfi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories, symlinks, devices, etc.)
		return fmt.Errorf("fCopy: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("fCopy: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return err
		}
	}
	if err = os.Link(src, dst); err == nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	err = out.Sync()
	return err
}

func fMove(src, dst string) error {
	err := fCopy(src, dst)
	if err != nil {
		log.Warn(err)
		return err
	}
	err = fDelete(src)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}

func fDownload(path, url string, basicAuth bool) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if basicAuth {
		req.SetBasicAuth(*masterBasicAuthUser, *masterBasicAuthPassword)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download file operation for url %s finished with status code %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return fWrite(path, string(body))
}

func createArchiveFromDir(dir, path string) error {

	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn(err)
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		log.Warn(err)
	}

	out, err := os.Create(path)
	if err != nil {
		log.Errorf("Error writing archive %s: %s", path, err)
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Iterate over files and add them to the tar archive
	for _, filePath := range files {
		file, err := os.Open(filePath)
		if err != nil {
			log.Warnf("Error writing archive %s: %s", path, err)
			return err
		}

		// Get FileInfo about our file providing file size, mode, etc.
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}

		// Create a tar Header from the FileInfo data
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			file.Close()
			return err
		}

		// path inside the archive relative to dir; filepath.Walk cleans the paths it
		// returns ("./ccd/alice" -> "ccd/alice"), so dir is cleaned the same way
		relPath, err := filepath.Rel(filepath.Clean(dir), filePath)
		if err != nil {
			file.Close()
			return err
		}
		header.Name = filepath.ToSlash(relPath)

		// Write file header to the tar archive
		err = tw.WriteHeader(header)
		if err != nil {
			file.Close()
			return err
		}

		// Copy file content to tar archive
		_, err = io.Copy(tw, file)
		if err != nil {
			file.Close()
			return err
		}
		file.Close()
	}

	return nil
}

func extractFromArchive(archive, path string) error {
	// Open the file which will be written into the archive
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()

	uncompressedStream, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("extractFromArchive: NewReader failed: %w", err)
	}

	tarReader := tar.NewReader(uncompressedStream)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("extractFromArchive: Next() failed: %w", err)
		}

		// never write outside of the destination directory
		if !filepath.IsLocal(header.Name) {
			return fmt.Errorf("extractFromArchive: illegal file path %q", header.Name)
		}
		target := filepath.Join(path, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("extractFromArchive: Mkdir() failed: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("extractFromArchive: Mkdir() failed: %w", err)
			}
			outFile, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("extractFromArchive: Create() failed: %w", err)
			}
			_, err = io.Copy(outFile, tarReader)
			outFile.Close()
			if err != nil {
				return fmt.Errorf("extractFromArchive: Copy() failed: %w", err)
			}

		default:
			return fmt.Errorf("extractFromArchive: unknown type: %q in %s", header.Typeflag, header.Name)
		}
	}
	return nil
}
