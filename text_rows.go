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
		// for PolarDB latest version, mysqlType for cipher is set to 244, unknown to mysql driver.
		if r.cryptor.Server_version == encdb_sdk.POLAR_1_1_14 && type_name != "ENCDB_CIPHER" {
			continue
		}
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
		// FIXME(yx): fix cipher conflict problem for RDS
		if r.cryptor.Server_version == encdb_sdk.RDS {
			encdb_cipher, err := encdb_sdk.ParseCipher(cipher_bytes)
			if err != nil {
				continue
			}
			algo, err := encdb_cipher.GetEncAlgo()
			if err != nil || (algo != encdb_sdk.AES_128_GCM && algo != encdb_sdk.SM4_128_GCM) {
				continue
			}
		}
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
