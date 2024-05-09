package encmysql

import (
	"database/sql/driver"
	"time"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"
)

type encmysqlConn struct {
	conn      driver.Conn
	encdbSDK  encdb_sdk.EncdbSDK // Each encmysqlConn should have a seperate sdk
	parseTime bool               // Parse time values to time.Time
	Loc       *time.Location     // Location for time.Time values
}

func (c *encmysqlConn) Begin() (driver.Tx, error) {
	return c.conn.Begin()
}

func (c *encmysqlConn) Close() error {
	return c.conn.Close()
}

func (c *encmysqlConn) Prepare(query string) (driver.Stmt, error) {
	mysqlStmt, err := c.conn.Prepare(query)
	return &encmysqlStmt{mysqlStmt, &c.encdbSDK.Cryptor, c.parseTime, c.Loc}, err
}

// Queryer interface
func (c *encmysqlConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	// This for sure works, as long as we are working with mysql driver.
	rows, err := c.conn.(driver.Queryer).Query(query, args)
	return &encmysqlTextRows{
		rows:      rows,
		cryptor:   &c.encdbSDK.Cryptor,
		parseTime: c.parseTime,
		Loc:       c.Loc}, err
}
