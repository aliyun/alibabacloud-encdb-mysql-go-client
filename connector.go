package encmysql

import (
	"context"
	"database/sql/driver"
	"time"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"
)

type encmysql_connector struct {
	connector driver.Connector
	parseTime bool           //Parse time values to time.Time
	Loc       *time.Location // Location for time.Time values
	Algo      encdb_sdk.SymmAlgo
	MEK       []byte
	Is_polar  bool
}

func (c *encmysql_connector) Connect(ctx context.Context) (driver.Conn, error) {
	mysqlConn, err := c.connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	sdk := encdb_sdk.EncdbSDK{
		Conn: &mysqlConn,
		Cryptor: encdb_sdk.Cryptor{
			MEK:  c.MEK,
			Algo: c.Algo,
		},
		Is_polar: c.Is_polar,
	}
	sdk.GetServerInfo()
	err = sdk.ProvisionMEK()
	if err != nil {
		return nil, err
	}
	return &encmysqlConn{mysqlConn, sdk, c.parseTime, c.Loc}, err
}

func (c *encmysql_connector) Driver() driver.Driver {
	return &EncMySQLDriver{}
}
