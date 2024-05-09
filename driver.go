package encmysql

import (
	"database/sql"
	"database/sql/driver"
	"encoding/hex"

	"github.com/aliyun/alibabacloud-encdb-mysql-go-client/encdb_sdk"

	"github.com/go-sql-driver/mysql"
)

type EncMySQLDriver struct {
	mysqlDriver *mysql.MySQLDriver
}

func (d *EncMySQLDriver) Open(dsn string) (driver.Conn, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	mek_str, exists := cfg.Params["MEK"]
	if !exists {
		panic("Error, you must configure MEK for a driver")
	}
	algo_str, exists := cfg.Params["ENC_ALGO"]
	if !exists {
		algo_str = encdb_sdk.SM4_128_CBC
	}
	dsn = RemoveParamFromDSN(dsn, "MEK")
	dsn = RemoveParamFromDSN(dsn, "ENC_ALGO")
	mysqlConn, err := d.mysqlDriver.Open(dsn)
	if err != nil {
		return nil, err
	}
	mek, err := hex.DecodeString(mek_str)
	if err != nil {
		panic(err)
	}
	sdk := encdb_sdk.EncdbSDK{
		Conn: &mysqlConn,
		Cryptor: encdb_sdk.Cryptor{
			MEK:  mek,
			Algo: encdb_sdk.SymmAlgo(algo_str),
		},
	}
	sdk.GetServerInfo()
	err = sdk.ProvisionMEK()
	if err != nil {
		return nil, err
	}
	return &encmysqlConn{
		conn:      mysqlConn,
		encdbSDK:  sdk,
		parseTime: cfg.ParseTime,
		Loc:       cfg.Loc,
	}, err
}

func (d *EncMySQLDriver) OpenConnector(dsn string) (driver.Connector, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	mek_str, exists := cfg.Params["MEK"]
	if !exists {
		panic("Error, you must configure MEK for a driver")
	}
	algo_str, exists := cfg.Params["ENC_ALGO"]
	if !exists {
		algo_str = encdb_sdk.SM4_128_CBC
	}
	dsn = RemoveParamFromDSN(dsn, "MEK")
	dsn = RemoveParamFromDSN(dsn, "ENC_ALGO")
	mysqlConnector, err := d.mysqlDriver.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	mek, _ := hex.DecodeString(mek_str)
	return &encmysql_connector{
		connector: mysqlConnector,
		parseTime: cfg.ParseTime,
		Loc:       cfg.Loc,
		MEK:       mek,
		Algo:      encdb_sdk.SymmAlgo(algo_str),
	}, err
}

func init() {
	sql.Register("encmysql", &EncMySQLDriver{mysqlDriver: &mysql.MySQLDriver{}})
}
