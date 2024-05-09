# README
这个项目是阿里云**全密态MySQL数据库**的Go语言驱动。参见:

[全密态PolarMySQL](https://help.aliyun.com/zh/polardb/polardb-for-mysql/user-guide/confidential-engine)

[全密态RDS MySQL](https://help.aliyun.com/zh/rds/apsaradb-rds-for-mysql/fully-encrypted-database)

## 安装
```go
go get github.com/aliyun/alibabacloud-encdb-mysql-go-client/v0.0.1
```

## 使用
本驱动实现了GoLang `database/sql/driver` 系列同用接口，用户只需要配置正确的DSN并将驱动名设置为`encmysql`，即可通过统一接口连接全密态数据库。
```go
mek := ...
encAlgo := ...

db, err := sql.Open("encmysql", "<username>:<password>@tcp(<hostname>:<port>)/<dbname>?MEK=<mek>&ENC_ALGO=<encAlgo>")
```
其中：mek是一个16位的16进制字符串，用于表示一个256位的密钥。例如：00112233445566778899aabbccddeeff

encAlgo是数据加密使用的算法，有以下选择：
- SM4_128_CBC
- SM4_128_CTR
- SM4_128_GCM
- SM4_128_ECB
- AES_128_CBC
- AES_128_CTR
- AES_128_GCM
- AES_128_ECB

## 一个demo
请先设置，将测试库中的test表a、b、c列加密。
```go
package main

import (
 "database/sql"
 "fmt"
 _ "github.com/aliyun/alibabacloud-encdb-mysql-go-client"
)

func main() {
 
 db, err := sql.Open("encmysql", "<username>:<password>@tcp(<hostname>:<port>)/<dbname>?MEK=00112233445566778899aabbccddeeff&ENC_ALGO=SM4_128_CBC")
 if err != nil {
 panic(err)
 }
 _, err = db.Exec("DROP TABLE IF EXISTS test")
 if err != nil {
 panic(err)
 }
 _, err = db.Exec(`create table test(a int, b text, c float)`)
 if err != nil {
 panic(err)
 }
 _, err = db.Exec(`insert into test set a = 0, b = 'test', c = 0.0`)
 if err != nil {
 panic(err)
 }
 rows, err := db.Query("SELECT * FROM test")
 rows.Next()
 var a int
 var b string
 var c float32

 err = rows.Scan(&a, &b, &c)
 fmt.Printf("read data: %d %s %f\n", a, b, c)
}
```