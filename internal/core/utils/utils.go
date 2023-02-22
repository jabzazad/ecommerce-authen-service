package utils

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	earthRadiusKM = 6371
)

// TrimSpace trim space
func TrimSpace(i interface{}, depth int) {
	e := reflect.ValueOf(i).Elem()
	for i := 0; i < e.NumField(); i++ {
		if depth < 3 && e.Type().Field(i).Type.Kind() == reflect.Struct {
			depth++
			TrimSpace(e.Field(i).Addr().Interface(), depth)
		}

		if e.Type().Field(i).Type.Kind() != reflect.String {
			continue
		}

		value := e.Field(i).Interface().(string)
		e.Field(i).SetString(strings.TrimSpace(value))
	}
}

// isValidCitizenID is valid citizenId
func isValidCitizenID(citizenID string) bool {
	if !regexCitizenID.MatchString(citizenID) {
		return false
	}

	sum, row := 0, 13
	citizenIDRune := []rune(citizenID)
	for _, n := range string(citizenIDRune) {
		number, _ := strconv.Atoi(string(n))
		sum += number * row
		row--

		if row == 1 {
			break
		}
	}

	citizenIDInt, _ := strconv.Atoi(citizenID)
	result := (11 - (int(sum) % 11)) % 10

	return (citizenIDInt % 10) == result
}

// DeleteMapping delete map
func DeleteMapping(s map[string]interface{}, fields []string) {
	for _, field := range fields {
		delete(s, field)
	}

}

// ReplaceMapping replace map
func ReplaceMapping(s map[string]interface{}, replaces, olds []string) {
	for i, replace := range replaces {
		s[replace] = s[olds[i]]
	}

	DeleteMapping(s, olds)
}

// DistanceKiloMeters distance kilo meter between 2 poin coordinate
// use harversine fomula ref: https://en.wikipedia.org/wiki/Haversine_formula
func DistanceKiloMeters(latFirst float64, lngFirst float64, latSecond float64, lngSecond float64) float64 {
	radianLatFirst := latFirst * math.Pi / 180
	radianLngFirst := lngFirst * math.Pi / 180
	radianLatSecond := latSecond * math.Pi / 180
	radianLngSecond := lngSecond * math.Pi / 180

	diffLat := radianLatSecond - radianLatFirst
	diffLon := radianLngSecond - radianLngFirst
	h := math.Pow(math.Sin(diffLat/2), 2) + math.Cos(radianLatFirst)*math.Cos(radianLatSecond)*math.Pow(math.Sin(diffLon/2), 2)
	distance := 2 * math.Asin(math.Sqrt(h))
	return earthRadiusKM * distance
}

// GetBindDataWithoutLast4Digit get binding data without last 4 digit
func GetBindDataWithoutLast4Digit(identificationNumber string) (binding string) {
	for i := 0; i < len(identificationNumber)-4; i++ {
		binding += "X"
	}

	return fmt.Sprint(binding, identificationNumber[len(identificationNumber)-4:])
}

// IntersectionString intersection from string array
func IntersectionString(a, b []string) []string {
	r := []string{}
	for _, i := range a {
		for _, j := range b {
			if i == j {
				r = append(r, i)
			}
		}
	}

	return r
}

// FindDuplicateFromSlice find duplicate item from slice
func FindDuplicateFromSlice(a []int64, b uint) bool {
	for _, object := range a {
		if uint(object) == b {
			return true
		}
	}

	return false
}

// ToChar to character
func ToChar(i int) rune {
	return rune('A' - 1 + i)
}

// GetAddress get address
func GetAddress(district, subdistrict, province string) string {
	if province == "กรุงเทพมหานคร" {
		return fmt.Sprintf("แขวง %s เขต %s จังหวัด %s", subdistrict, district, province)
	}
	return fmt.Sprintf("ตำบล %s อำเภอ %s จังหวัด %s", subdistrict, district, province)
}

// GetFullAddress get full address
func GetFullAddress(firstName, phoneNumber, email, district, subdistrict, province, postcode, address string) string {
	return fmt.Sprintf("ชื่อ %s เบอร์โทรศัพท์ %s อีเมล์ %s ที่อยู่ %s %s ที่อยู่เพิ่มเติม %s", firstName, phoneNumber, email,
		GetAddress(district, subdistrict, province), postcode, address)
}

// ConvertStructToJSONRawMessage convert struct to json
func ConvertStructToJSONRawMessage(i interface{}) (json.RawMessage, error) {
	encode, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	raw := json.RawMessage(string(encode))
	return raw, nil
}

// CheckDuplicateID check duplicate id
func CheckDuplicateID(imageID []int64, request []int64) bool {
	for _, i := range imageID {
		isFound := false
		for _, j := range request {
			if i == j {
				isFound = true
			}
		}

		if !isFound {
			return false
		}
	}

	return true
}

// Difference differentiate string
func Difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// CastType cast type
func CastTypeIntOrStringReturnInt[T string | int](a T) int {
	var output int
	switch any(a).(type) {
	case string:
		output, _ = strconv.Atoi(any(a).(string))

	case int:
		output = any(a).(int)
	}

	return output
}

// GetFileContentType get file content type
func GetFileContentType(ouput *os.File) (string, error) {

	// to sniff the content type only the first
	// 512 bytes are used.

	buf := make([]byte, 512)

	_, err := ouput.Read(buf)

	if err != nil {
		return "", err
	}

	// the function that actually does the trick
	contentType := http.DetectContentType(buf)

	return contentType, nil
}

// GetFileContentType get file content type
func ValidWEBP(ouput *os.File) (bool, error) {
	// to sniff the content type only the first
	// 512 bytes are used.

	buf := make([]byte, 512)

	_, err := ouput.Read(buf)

	if err != nil {
		return false, err
	}

	return http.DetectContentType(buf) == "image/webp", nil
}

func FindClosestTimeFromSlice(a []time.Time, b time.Time) time.Time {
	cloz_dict := make(map[int]time.Time)
	for _, date := range a {
		cloz_dict[int(math.Abs(b.Sub(date).Seconds()))] = date
	}

	min := 9999999999
	var res time.Time
	for key, date := range cloz_dict {
		if key < min {
			min = key
			res = date
		}
	}
	return res
}
