package unique

import "github.com/rs/xid"

// NewXid new xid
func NewXid() string {
	return xid.New().String()
}
