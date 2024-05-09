package encdb_sdk

import (
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

func TestGetServerInfo(t *testing.T) {
	db, err := sql.Open("mysql", "yangxiao:12345@tcp(11.160.51.160:4400)/test")
	if err != nil {
		panic(err)
	}
	mysqlConn, err := db.Driver().Open("yangxiao:12345@tcp(11.160.51.160:4400)/test")
	if err != nil {
		panic(err)
	}
	encdb_sdk := EncdbSDK{
		Conn:    &mysqlConn,
		Cryptor: Cryptor{},
	}
	encdb_sdk.GetServerInfo()
}

func TestGetServerInfoAndSetMEK(t *testing.T) {
	db, err := sql.Open("mysql", "yangxiao:12345@tcp(11.160.51.160:4400)/test")
	if err != nil {
		panic(err)
	}
	mysqlConn, err := db.Driver().Open("yangxiao:12345@tcp(11.160.51.160:4400)/test")
	if err != nil {
		panic(err)
	}
	encdb_sdk := EncdbSDK{
		Conn:    &mysqlConn,
		Cryptor: Cryptor{},
	}
	encdb_sdk.GetServerInfo()
	_ = encdb_sdk.ProvisionMEK()
}
