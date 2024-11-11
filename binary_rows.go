package encmysql

import (
	"database/sql/driver"
	"encoding/base64"
	"strings"
	"time"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"
)

type encmysqlBinaryRows struct {
	rows      driver.Rows
	cryptor   *encdb_sdk.Cryptor
	parseTime bool           // Parse time values to time.Time
	Loc       *time.Location // Location for time.Time values
}

func (r *encmysqlBinaryRows) Columns() []string {
	return r.rows.Columns()
}

func (r *encmysqlBinaryRows) Close() error {
	return r.rows.Close()
}

func (r *encmysqlBinaryRows) Next(dest []driver.Value) error {
	err := r.rows.Next(dest)
	if err != nil {
		return err
	}
	for i := 0; i < len(dest); i++ {
		if dest[i] == nil {
			continue
		}
		type_name := r.rows.(driver.RowsColumnTypeDatabaseTypeName).ColumnTypeDatabaseTypeName(i)
		// for PolarDB latest version, mysqlType for cipher is set to 244, unknown to mysql driver.
		if r.cryptor.Server_version == encdb_sdk.POLAR_1_1_14 && type_name != "ENCDB_CIPHER" {
			continue
		}
		_, scale, _ := r.rows.(driver.RowsColumnTypePrecisionScale).ColumnTypePrecisionScale(i)
		is_unsigned := strings.Contains(type_name, "UNSIGNED")
		cipher_bytes, ok := dest[i].([]uint8)
		if !ok {
			continue
		}
		cipher_str := string(cipher_bytes)
		cipher_bytes, err = base64.StdEncoding.DecodeString(cipher_str)
		if err != nil {
			continue
		}
		plaintext, m_type, err := r.cryptor.Decrypt(cipher_bytes)
		if err != nil {
			continue
		}
		// parse plaintext in text protocol
		dest[i], err = DecodeBinaryField(plaintext, m_type, is_unsigned, r.parseTime, r.Loc, uint8(scale))
		if err != nil {
			return err
		}
	}
	return nil
}
