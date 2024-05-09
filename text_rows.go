package encmysql

import (
	"database/sql/driver"
	"encoding/base64"
	"strings"
	"time"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"
)

type encmysqlTextRows struct {
	rows      driver.Rows
	cryptor   *encdb_sdk.Cryptor
	parseTime bool           // Parse time values to time.Time
	Loc       *time.Location // Location for time.Time values
}

func (r *encmysqlTextRows) Columns() []string {
	return r.rows.Columns()
}

func (r *encmysqlTextRows) Close() error {
	return r.rows.Close()
}

func (r *encmysqlTextRows) Next(dest []driver.Value) error {
	err := r.rows.Next(dest)
	if err != nil {
		return err
	}
	for i := 0; i < len(dest); i++ {
		if dest[i] == nil {
			continue
		}
		type_name := r.rows.(driver.RowsColumnTypeDatabaseTypeName).ColumnTypeDatabaseTypeName(i)
		is_unsigned := strings.Contains(type_name, "UNSIGNED")
		cipher_base64_bytes, ok := dest[i].([]uint8)
		if !ok {
			continue
		}
		cipher_base64_str := string(cipher_base64_bytes)
		if !ok {
			continue
		}
		cipher_bytes, _ := base64.StdEncoding.DecodeString(cipher_base64_str)
		plaintext, m_type, err := r.cryptor.Decrypt(cipher_bytes)
		if err != nil {
			continue
		}
		// parse plaintext in text protocol
		dest[i], err = DecodeTextField(plaintext, m_type, is_unsigned, r.parseTime, r.Loc)
		if err != nil {
			return err
		}
	}
	return nil
}
