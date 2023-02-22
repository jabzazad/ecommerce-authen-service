// Package fileutil is a core fileutil package
package fileutil

import (
	"ecommerce-authen/internal/core/utils"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

const (
	// FileKey key single file
	FileKey = "file"
	// FilesKey key multi files
	FilesKey = "files"
	// Original original file name
	Original = "original"
	// Thumbnail thumbnail file name
	Thumbnail = "thumbnail"
)

// UploadFile upload file
func UploadFile(r *http.Request, maxMemory int64) (multipart.File, *multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		logrus.Error("[UploadFile] parses a request body as multipart/form-data error: ", err)
		return nil, nil, err
	}

	return r.FormFile(FileKey)
}

// UploadFiles upload file
func UploadFiles(r *http.Request, maxMemory int64) ([]*multipart.FileHeader, error) {
	if err := r.ParseMultipartForm(maxMemory); err != nil {
		logrus.Error("[UploadFile] parses a request body as multipart/form-data error: ", err)
		return nil, err
	}

	return r.MultipartForm.File[FilesKey], nil
}

// File file model
type File struct {
	Filename string
	Dir      string
	Type     string
}

// DownloadFromURL download from url
func DownloadFromURL(URL string) (io.Reader, error) {
	//Get the response bytes from the url
	response, err := http.Get(URL)
	if err != nil {
		return nil, err
	}

	return response.Body, nil
}

// New new file
func New(src io.Reader, fileName string) (*File, error) {
	dir, err := os.MkdirTemp("", "template-")
	if err != nil {
		return nil, err
	}

	dst, err := os.Create(fmt.Sprintf("%s/%s", dir, fileName))
	if err != nil {
		return nil, err
	}
	defer func() { _ = dst.Close() }()
	if _, err = io.Copy(dst, src); err != nil {
		return nil, err
	}

	file := &File{
		Filename: fileName,
		Dir:      dir,
	}

	f, err := os.Open(file.Path())
	if err != nil {
		log.Fatalln(err)
	}
	defer func() { _ = f.Close() }()

	contentType, err := utils.GetFileContentType(f)
	if err != nil {
		return nil, err
	}

	file.Type = contentType

	return file, nil
}

// Path file path
func (f *File) Path() string {
	return fmt.Sprintf("%s/%s", f.Dir, f.Filename)
}

// ContentType content type
func (f *File) ContentType() string {
	return f.Type
}

// Name file name
func (f *File) Name() string {
	return f.Filename
}

// Close removes path
func (f *File) Close() error {
	return os.RemoveAll(f.Dir)
}

// Extension extension file
func (f *File) Extension() string {
	return filepath.Ext(f.Filename)
}

// ScreenShot screen shot video
func (f *File) ScreenShot(uuid string) (string, error) {
	output := fmt.Sprintf("%s/%s_%s.jpeg", f.Dir, uuid, Thumbnail)
	cmd := exec.Command("ffmpeg", "-ss", "00:00:01.000", "-i", f.Path(), "-vframes", "1", "-vf", "scale=640:-1", output)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return output, nil
}
