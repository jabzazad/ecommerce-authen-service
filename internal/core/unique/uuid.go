// Package unique is a core unique package
package unique

import (
	"github.com/google/uuid"
)

// UUID UUID
func UUID() string {
	return uuid.New().String()
}
