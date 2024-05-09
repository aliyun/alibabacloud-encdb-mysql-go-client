package encmysql

import (
	"database/sql/driver"
	"time"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"
)

type encmysqlStmt struct {
	stmt      driver.Stmt
	cryptor   *encdb_sdk.Cryptor
	parseTime bool           // Parse time values to time.Time
	Loc       *time.Location // Location for time.Time values
}

func (s *encmysqlStmt) Close() error {
	return s.stmt.Close()
}

func (s *encmysqlStmt) NumInput() int {
	return s.stmt.NumInput()
}

func (s *encmysqlStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.stmt.Exec(args)
}

func (s *encmysqlStmt) Query(args []driver.Value) (driver.Rows, error) {
	mysqlRows, err := s.stmt.Query(args)
	return &encmysqlBinaryRows{mysqlRows, s.cryptor, s.parseTime, s.Loc}, err
}
