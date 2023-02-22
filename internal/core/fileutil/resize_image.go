package fileutil

import (
	"fmt"
	"image"
	"image/jpeg"
	"os"

	"github.com/disintegration/imaging"
)

// ImagePath image path
type ImagePath struct {
	OriginalPath string
	SmallPath    string
	MediumPath   string
	LargePath    string
}

const (
	// UserKey key user
	UserKey = "users"
	// UserProfileSize user profile size
	UserProfileSize = 128
	// SmallName small name
	SmallName = "small.jpg"
	// SmallSize small size
	SmallSize = 640
	// MediumName medium
	MediumName = "medium.jpg"
	// MediumSize medium size
	MediumSize = 800
	// LargeName large
	LargeName = "large.jpg"
	// LargeSize large size
	LargeSize = 1280
)

// ResizeImage resize image
func (f *File) ResizeImage(prefix string) (*ImagePath, error) {
	i := &ImagePath{
		OriginalPath: f.Path(),
	}
	original, err := imaging.Open(f.Path())
	if err != nil {
		return nil, err
	}

	size := SmallSize
	if prefix == UserKey {
		size = UserProfileSize
	}
	smallPath := fmt.Sprintf("%s/%s", f.Dir, SmallName)
	err = resizeAndSaveImage(original, size, smallPath)
	if err != nil {
		return nil, err
	}
	i.SmallPath = smallPath

	// mediumPath := fmt.Sprintf("%s/%s", f.Dir, MediumName)
	// err = resizeAndSaveImage(original, MediumSize, mediumPath)
	// if err != nil {
	// 	return nil, err
	// }
	// i.MediumPath = mediumPath

	largePath := fmt.Sprintf("%s/%s", f.Dir, LargeName)
	err = resizeAndSaveImage(original, LargeSize, largePath)
	if err != nil {
		return nil, err
	}
	i.LargePath = largePath

	return i, nil
}

func resizeAndSaveImage(original image.Image, size int, filepath string) error {
	var im *image.NRGBA
	if original.Bounds().Size().X > original.Bounds().Size().Y {
		im = imaging.Resize(original, size, 0, imaging.Lanczos)
	} else {
		im = imaging.Resize(original, 0, size, imaging.Lanczos)
	}
	dst, err := os.Create(filepath)
	if err != nil {
		return err
	}

	defer func() {
		_ = dst.Close()
	}()

	err = jpeg.Encode(dst, im, &jpeg.Options{
		Quality: 80,
	})
	if err != nil {
		return err
	}

	return nil
}
