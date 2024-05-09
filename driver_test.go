package encmysql

import (
	"database/sql"
	"testing"
)

// user:pwd@tcp(host:port)/db?MEK=00112233445566778899aabbccddeeff
const rds_dsn = "ruanbu:123456Abc!@tcp(rm-bp1r69e83i61e6g4kho.mysql.rds.aliyuncs.com:3306)/test?MEK=00112233445566778899aabbccddeeff"
const polar_dsn = "ruanbu:123456Abc!@tcp(pc-bp1c34eh5hi0jf305-public.rwlb.rds.aliyuncs.com:3306)/test?MEK=00112233445566778899aabbccddeeff"

func TestNormalStatementsOnRDSMySQL(t *testing.T) {
	dsns := [2]string{rds_dsn + "&parseTime=true", rds_dsn + "&parseTime=false"}
	encrypts := [2]bool{false, true}
	for i := 0; i < len(dsns); i++ {
		for j := 0; j < len(encrypts); j++ {
			dsn := dsns[i]
			db, err := sql.Open("encmysql", dsn)
			if encrypts[j] {
				_, err = db.Exec("SELECT encdb_rule_op('add','[{\"name\":\"golang_rule\",\"enabled\":true,\"meta\":{\"databases\":[\"test_golang\"],\"tables\":[\"*\"],\"columns\":[\"*\"]}}]')")
				if err != nil {
					panic(err)
				}
			} else {
				_, _ = db.Exec("SELECT encdb_rule_op('delete','\"golang_rule\"')")
				if err != nil {
					panic(err)
				}
			}
			_, err = db.Exec("DROP TABLE IF EXISTS t1")
			if err != nil {
				panic(err)
			}
			_, err = db.Exec(`create table t1 (c_int_null int,
				c_tinyint tinyint, c_smallint smallint,
				c_mediumint mediumint, c_int int, c_bigint bigint,
				c_float float(10), c_double double, c_decimal decimal(10,3),
				c_bit bit(64),
				c_year year(4), c_date date, c_time time(3),
				c_datetime datetime(6), c_timestamp timestamp,
				c_char char(10) charset latin1,
				c_varchar varchar(100) charset utf8mb4,
				c_binary binary(10), c_varbinary varbinary(100),
				c_text text, c_blob blob,
				c_enum enum('one', 'two', 'three'),
				c_set set('red', 'blue', 'yellow'), c_json json)`)
			if err != nil {
				panic(err)
			}
			_, err = db.Exec(`insert into t1 set
				c_tinyint = -1, c_smallint = 10000, c_mediumint = 50000, c_int = 1000000,
				c_bigint = 100000000000,
				c_float = 1.1111, c_double = 1000.00001, c_decimal = 1.234,
				c_bit = b'1000001',
				c_year = 2023, c_date = "2023-10-1", c_time = "15:24:25.123",
				c_datetime = "2023-10-1 15:24:25.123456",
				c_timestamp = "2023-10-1 15:24:25.123456",
				c_char = "0123456789", c_varchar = repeat("a", 100),
				c_binary = "0123456789", c_varbinary = repeat("A", 20),
				c_text = repeat("A", 300), c_blob = repeat("A", 1000),
				c_enum = 'two', c_set = 'red,blue',
				c_json = '{"key1": "value1", "key2": "value2"}'`)
			if err != nil {
				panic(err)
			}
			rows, err := db.Query("SELECT * FROM t1")
			rows.Next()
			var nullint *int
			var tinyint, smallint, mediumint, vint, bigint, year int
			var vfloat, vdecimal float32
			var vdouble float64
			var date, time, datetime, timestamp, char, varchar, txt, venum, vset, vjson string
			var vbyte, binary, varbinary, blob []byte

			err = rows.Scan(&nullint, &tinyint, &smallint, &mediumint, &vint, &bigint, &vfloat, &vdouble, &vdecimal,
				&vbyte, &year, &date, &time, &datetime, &timestamp, &char, &varchar, &binary, &varbinary,
				&txt, &blob, &venum, &vset, &vjson)
			if err != nil {
				panic(err.Error())
			}
			if tinyint != -1 {
				t.Errorf("Unexpected output %d, expecting %d", tinyint, -1)
			}
			if smallint != 10000 {
				t.Errorf("Unexpected output %d, expecting %d", smallint, 10000)
			}
			if mediumint != 50000 {
				t.Errorf("Unexpected output %d, expecting %d", mediumint, 50000)
			}
			if vint != 1000000 {
				t.Errorf("Unexpected output %d, expecting %d", vint, 1000000)
			}
			if bigint != 100000000000 {
				t.Errorf("Unexpected output %d, expecting %d", bigint, 100000000000)
			}
			if vfloat != 1.1111 {
				t.Errorf("Unexpected output %f, expecting %f", vfloat, 1.1111)
			}
			if vdouble != 1000.00001 {
				t.Errorf("Unexpected output %f, expecting %f", vdouble, 1000.00001)
			}
			if vdecimal != 1.234 {
				t.Errorf("Unexpected output %f, expecting %f", vdecimal, 1.234)
			}
			if len(vbyte) != 8 || uint8(vbyte[7]) != 0b1000001 {
				t.Errorf("Unexpected output %d, expecting %d", uint8(vbyte[7]), 0b1000001)
			}
			if year != 2023 {
				t.Errorf("Unexpected output %d, expecting %d", year, 2023)
			}
			if date != "2023-10-01T00:00:00Z" && date != "2023-10-01" {
				t.Errorf("Unexpected output %s, expecting %s or %s", date, "2023-10-01", "2023-10-01T00:00:00Z")
			}
			if time != "15:24:25.123" {
				t.Errorf("Unexpected output %s, expecting %s", time, "15:24:25.123")
			}
		}
	}
}

func TestPrepareStatementsOnRDSMySQL(t *testing.T) {
	dsns := [2]string{rds_dsn + "&parseTime=true", rds_dsn + "&parseTime=false"}
	encrypts := [2]bool{false, true}
	for i := 0; i < len(dsns); i++ {
		for j := 0; j < len(encrypts); j++ {
			dsn := dsns[i]
			db, err := sql.Open("encmysql", dsn)
			if encrypts[j] {
				_, err = db.Exec("SELECT encdb_rule_op('add','[{\"name\":\"golang_rule\",\"enabled\":true,\"meta\":{\"databases\":[\"test_golang\"],\"tables\":[\"*\"],\"columns\":[\"*\"]}}]')")
				if err != nil {
					panic(err)
				}
			} else {
				_, _ = db.Exec("SELECT encdb_rule_op('delete','\"golang_rule\"')")
				if err != nil {
					panic(err)
				}
			}
			_, err = db.Exec("DROP TABLE IF EXISTS t1")
			if err != nil {
				panic(err)
			}
			_, err = db.Exec(`create table t1 (c_int_null int,
				c_tinyint tinyint, c_smallint smallint,
				c_mediumint mediumint, c_int int, c_bigint bigint,
				c_float float(10), c_double double, c_decimal decimal(10,3),
				c_bit bit(64),
				c_year year(4), c_date date, c_time time(3),
				c_datetime datetime(6), c_timestamp timestamp,
				c_char char(10) charset latin1,
				c_varchar varchar(100) charset utf8mb4,
				c_binary binary(10), c_varbinary varbinary(100),
				c_text text, c_blob blob,
				c_enum enum('one', 'two', 'three'),
				c_set set('red', 'blue', 'yellow'), c_json json)`)
			if err != nil {
				panic(err)
			}
			_, err = db.Exec(`insert into t1 set
				c_tinyint = -1, c_smallint = 10000, c_mediumint = 50000, c_int = 1000000,
				c_bigint = 100000000000,
				c_float = 1.1111, c_double = 1000.00001, c_decimal = 1.234,
				c_bit = b'1000001',
				c_year = 2023, c_date = "2023-10-1", c_time = "15:24:25.123",
				c_datetime = "2023-10-1 15:24:25.123456",
				c_timestamp = "2023-10-1 15:24:25.123456",
				c_char = "0123456789", c_varchar = repeat("a", 100),
				c_binary = "0123456789", c_varbinary = repeat("A", 20),
				c_text = repeat("A", 300), c_blob = repeat("A", 1000),
				c_enum = 'two', c_set = 'red,blue',
				c_json = '{"key1": "value1", "key2": "value2"}'`)
			if err != nil {
				panic(err)
			}
			stmt, err := db.Prepare("SELECT * FROM t1")
			var nullint *int
			var tinyint, smallint, mediumint, vint, bigint, year int
			var vfloat, vdecimal float32
			var vdouble float64
			var date, time, datetime, timestamp, char, varchar, txt, venum, vset, vjson string
			var vbyte, binary, varbinary, blob []byte
			rows, err := stmt.Query()
			rows.Next()
			err = rows.Scan(&nullint, &tinyint, &smallint, &mediumint, &vint, &bigint, &vfloat, &vdouble, &vdecimal,
				&vbyte, &year, &date, &time, &datetime, &timestamp, &char, &varchar, &binary, &varbinary,
				&txt, &blob, &venum, &vset, &vjson)
			if err != nil {
				panic(err.Error())
			}
			if tinyint != -1 {
				t.Errorf("Unexpected output %d, expecting %d", tinyint, -1)
			}
			if smallint != 10000 {
				t.Errorf("Unexpected output %d, expecting %d", smallint, 10000)
			}
			if mediumint != 50000 {
				t.Errorf("Unexpected output %d, expecting %d", mediumint, 50000)
			}
			if vint != 1000000 {
				t.Errorf("Unexpected output %d, expecting %d", vint, 1000000)
			}
			if bigint != 100000000000 {
				t.Errorf("Unexpected output %d, expecting %d", bigint, 100000000000)
			}
			if vfloat != 1.1111 {
				t.Errorf("Unexpected output %f, expecting %f", vfloat, 1.1111)
			}
			if vdouble != 1000.00001 {
				t.Errorf("Unexpected output %f, expecting %f", vdouble, 1000.00001)
			}
			if vdecimal != 1.234 {
				t.Errorf("Unexpected output %f, expecting %f", vdecimal, 1.234)
			}
			if len(vbyte) != 8 || uint8(vbyte[7]) != 0b1000001 {
				t.Errorf("Unexpected output %d, expecting %d", uint8(vbyte[7]), 0b1000001)
			}
			if year != 2023 {
				t.Errorf("Unexpected output %d, expecting %d", year, 2023)
			}
			if date != "2023-10-01T00:00:00Z" && date != "2023-10-01" {
				t.Errorf("Unexpected output %s, expecting %s or %s", date, "2023-10-01", "2023-10-01T00:00:00Z")
			}
			if time != "15:24:25.123" && time != "15:24:25" {
				t.Errorf("Unexpected output %s, expecting %s or %s", time, "15:24:25.123", "15:24:25")
			}
		}
	}
}

func TestNormalStatementsOnPolarDBMySQL(t *testing.T) {
	db, err := sql.Open("encmysql", polar_dsn)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("DROP TABLE IF EXISTS t1")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`create table t1 (c_int_null int,
		c_tinyint tinyint, c_smallint smallint,
		c_mediumint mediumint, c_int int, c_bigint bigint,
		c_float float(10), c_double double, c_decimal decimal(10,3),
		c_bit bit(64),
		c_year year(4), c_date date, c_time time(3),
		c_datetime datetime(6), c_timestamp timestamp,
		c_char char(10) charset latin1,
		c_varchar varchar(100) charset utf8mb4,
		c_binary binary(10), c_varbinary varbinary(100),
		c_text text, c_blob blob,
		c_enum enum('one', 'two', 'three'),
		c_set set('red', 'blue', 'yellow'), c_json json)`)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`insert into t1 set
		c_tinyint = -1, c_smallint = 10000, c_mediumint = 50000, c_int = 1000000,
		c_bigint = 100000000000,
		c_float = 1.1111, c_double = 1000.00001, c_decimal = 1.234,
		c_bit = b'1000001',
		c_year = 2023, c_date = "2023-10-1", c_time = "15:24:25.123",
		c_datetime = "2023-10-1 15:24:25.123456",
		c_timestamp = "2023-10-1 15:24:25.123456",
		c_char = "0123456789", c_varchar = repeat("a", 100),
		c_binary = "0123456789", c_varbinary = repeat("A", 20),
		c_text = repeat("A", 300), c_blob = repeat("A", 1000),
		c_enum = 'two', c_set = 'red,blue',
		c_json = '{"key1": "value1", "key2": "value2"}'`)
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM t1")
	rows.Next()
	var nullint *int
	var tinyint, smallint, mediumint, vint, bigint, year int
	var vfloat, vdecimal float32
	var vdouble float64
	var date, time, datetime, timestamp, char, varchar, txt, venum, vset, vjson string
	var vbyte, binary, varbinary, blob []byte

	err = rows.Scan(&nullint, &tinyint, &smallint, &mediumint, &vint, &bigint, &vfloat, &vdouble, &vdecimal,
		&vbyte, &year, &date, &time, &datetime, &timestamp, &char, &varchar, &binary, &varbinary,
		&txt, &blob, &venum, &vset, &vjson)
	if err != nil {
		panic(err.Error())
	}
	if tinyint != -1 {
		t.Errorf("Unexpected output %d, expecting %d", tinyint, -1)
	}
	if smallint != 10000 {
		t.Errorf("Unexpected output %d, expecting %d", smallint, 10000)
	}
	if mediumint != 50000 {
		t.Errorf("Unexpected output %d, expecting %d", mediumint, 50000)
	}
	if vint != 1000000 {
		t.Errorf("Unexpected output %d, expecting %d", vint, 1000000)
	}
	if bigint != 100000000000 {
		t.Errorf("Unexpected output %d, expecting %d", bigint, 100000000000)
	}
	if vfloat != 1.1111 {
		t.Errorf("Unexpected output %f, expecting %f", vfloat, 1.1111)
	}
	if vdouble != 1000.00001 {
		t.Errorf("Unexpected output %f, expecting %f", vdouble, 1000.00001)
	}
	if vdecimal != 1.234 {
		t.Errorf("Unexpected output %f, expecting %f", vdecimal, 1.234)
	}
	if len(vbyte) != 8 || uint8(vbyte[7]) != 0b1000001 {
		t.Errorf("Unexpected output %d, expecting %d", uint8(vbyte[7]), 0b1000001)
	}
	if year != 2023 {
		t.Errorf("Unexpected output %d, expecting %d", year, 2023)
	}
	if date != "2023-10-01" {
		t.Errorf("Unexpected output %s, expecting %s", date, "2023-10-01")
	}
	if time != "15:24:25.123" {
		t.Errorf("Unexpected output %s, expecting %s", time, "15:24:25.123")
	}
}

func TestPrepareStatementsOnPolarDBMySQL(t *testing.T) {
	db, err := sql.Open("encmysql", polar_dsn)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("DROP TABLE IF EXISTS t1")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`create table t1 (c_int_null int,
		c_tinyint tinyint, c_smallint smallint,
		c_mediumint mediumint, c_int int, c_bigint bigint,
		c_float float(10), c_double double, c_decimal decimal(10,3),
		c_bit bit(64),
		c_year year(4), c_date date, c_time time(3),
		c_datetime datetime(6), c_timestamp timestamp,
		c_char char(10) charset latin1,
		c_varchar varchar(100) charset utf8mb4,
		c_binary binary(10), c_varbinary varbinary(100),
		c_text text, c_blob blob,
		c_enum enum('one', 'two', 'three'),
		c_set set('red', 'blue', 'yellow'), c_json json)`)
	if err != nil {
		panic(err)
	}
	_, err = db.Exec(`insert into t1 set
	c_tinyint = -1, c_smallint = 10000, c_mediumint = 50000, c_int = 1000000,
	c_bigint = 100000000000,
	c_float = 1.1111, c_double = 1000.00001, c_decimal = 1.234,
	c_bit = b'1000001',
	c_year = 2023, c_date = "2023-10-1", c_time = "15:24:25.123",
	c_datetime = "2023-10-1 15:24:25.123456",
	c_timestamp = "2023-10-1 15:24:25.123456",
	c_char = "0123456789", c_varchar = repeat("a", 100),
	c_binary = "0123456789", c_varbinary = repeat("A", 20),
	c_text = repeat("A", 300), c_blob = repeat("A", 1000),
	c_enum = 'two', c_set = 'red,blue',
	c_json = '{"key1": "value1", "key2": "value2"}'`)
	if err != nil {
		panic(err)
	}
	stmt, err := db.Prepare("SELECT * FROM t1")
	var nullint *int
	var tinyint, smallint, mediumint, vint, bigint, year int
	var vfloat, vdecimal float32
	var vdouble float64
	var date, time, datetime, timestamp, char, varchar, txt, venum, vset, vjson string
	var vbyte, binary, varbinary, blob []byte
	rows, err := stmt.Query()
	if err != nil {
		panic(err.Error())
	}
	rows.Next()
	err = rows.Scan(&nullint, &tinyint, &smallint, &mediumint, &vint, &bigint, &vfloat, &vdouble, &vdecimal,
		&vbyte, &year, &date, &time, &datetime, &timestamp, &char, &varchar, &binary, &varbinary,
		&txt, &blob, &venum, &vset, &vjson)
	if err != nil {
		panic(err.Error())
	}
	if tinyint != -1 {
		t.Errorf("Unexpected output %d, expecting %d", tinyint, -1)
	}
	if smallint != 10000 {
		t.Errorf("Unexpected output %d, expecting %d", smallint, 10000)
	}
	if mediumint != 50000 {
		t.Errorf("Unexpected output %d, expecting %d", mediumint, 50000)
	}
	if vint != 1000000 {
		t.Errorf("Unexpected output %d, expecting %d", vint, 1000000)
	}
	if bigint != 100000000000 {
		t.Errorf("Unexpected output %d, expecting %d", bigint, 100000000000)
	}
	if vfloat != 1.1111 {
		t.Errorf("Unexpected output %f, expecting %f", vfloat, 1.1111)
	}
	if vdouble != 1000.00001 {
		t.Errorf("Unexpected output %f, expecting %f", vdouble, 1000.00001)
	}
	if vdecimal != 1.234 {
		t.Errorf("Unexpected output %f, expecting %f", vdecimal, 1.234)
	}
	if len(vbyte) != 8 || uint8(vbyte[7]) != 0b1000001 {
		t.Errorf("Unexpected output %d, expecting %d", uint8(vbyte[7]), 0b1000001)
	}
	if year != 2023 {
		t.Errorf("Unexpected output %d, expecting %d", year, 2023)
	}
	if date != "2023-10-01" {
		t.Errorf("Unexpected output %s, expecting %s", date, "2023-10-01")
	}
}
