# README
这个项目是阿里云**全密态MySQL数据库**的Go语言驱动。参见:

[全密态PolarMySQL](https://help.aliyun.com/zh/polardb/polardb-for-mysql/user-guide/confidential-engine)

[全密态RDS MySQL](https://help.aliyun.com/zh/rds/apsaradb-rds-for-mysql/fully-encrypted-database)

对于任何文档不能解决的疑问、诉求，请通过阿里云官网RDS MySQL或者PolarDB MySQL产品工单渠道进行提问。

## 安装
```go
go get github.com/aliyun/alibabacloud-encdb-mysql-go-client@latest
```

## 使用
本驱动实现了GoLang `database/sql/driver` 系列通用接口，用户只需要配置正确的DSN并将驱动名设置为`encmysql`，即可通过统一接口连接全密态数据库。
```go
mek := ...
encAlgo := ...

db, err := sql.Open("encmysql", "<username>:<password>@tcp(<hostname>:<port>)/<dbname>?MEK=<mek>&ENC_ALGO=<encAlgo>")
```
其中：mek是一个32位的16进制字符串，用于表示一个128位的密钥。例如：00112233445566778899aabbccddeeff

encAlgo是数据加密使用的算法，有以下选择：
- SM4_128_CBC
- SM4_128_CTR
- SM4_128_GCM
- SM4_128_ECB
- AES_128_CBC
- AES_128_CTR
- AES_128_GCM
- AES_128_ECB

### 接入Web框架
本驱动提供了和社区驱动一致的接口，可以无缝接入Gin、Gorm、Xorm等框架。
#### 接入Gorm
Gorm本身提供了用户使用自定义驱动的方案，参见[Gorm使用自定义Driver](https://gorm.io/docs/connecting_to_the_database.html#Customize-Driver)。
下面是一个示例。业务侧仅需在初始化Gorm的阶段接入本驱动，业务代码无需改造:
```go
mysqlDb, err := sql.Open("encmysql", "user:password@tcp(host:port)/test?parseTime=false&MEK=00112233445566778899aabbccddeeff")
if err != nil {
    panic(err)
}
db, err := gorm.Open(mysql.New(mysql.Config{
    Conn: mysqlDb,
}), &gorm.Config{})
if err != nil {
    panic(err)
}
```
#### 接入老版本Xorm（以0.6.4为例）
Xorm本身没有直接提供接入自定义驱动的方式，但是我们可以通过一些简单的初始化阶段配置让Xorm进行支持。
对于较老版本的Xorm，它依赖`github.com/go-xorm/core`这个库。我们以0.6.4为例，首先在import语句中，加入以下依赖：
```go
import ("github.com/go-xorm/core")
```
需要注意的是，这是一个来自`xorm.io/xorm`库本身的间接依赖。接下来，在您业务代码的的`init`函数中，加入以下内容：
```go
func init() {
	core.RegisterDriver("encmysql", core.QueryDriver("mysql"))
	core.RegisterDialect("encmysql", func() core.Dialect { return core.QueryDialect("mysql") })
}
```
完成以上配置后，您可以在代码中像使用一个普通的数据库驱动一样调用`encmysql`。
```go
engine, err := xorm.NewEngine("encmysql", "user:password@tcp(host:port)/test?parseTime=false&MEK=00112233445566778899aabbccddeeff")
```
#### 新版本Xorm（以1.3.9为例）
新版本Xorm不再依赖core库。我们只需要在import中加入一个Xorm子模块依赖：
```go
import ("xorm.io/xorm/dialects")
```
接下来，在您业务代码的的`init`函数中，加入以下内容：
```go
func init() {
	dialects.RegisterDialect("encmysql", func() dialects.Dialect { return dialects.QueryDialect("mysql") })
	dialects.RegisterDriver("encmysql", dialects.QueryDriver("mysql"))
}
```
完成以上配置后，您可以在代码中像使用一个普通的数据库驱动一样调用`encmysql`。

### 一个demo
请先设置，将测试库中的test表a、b、c列加密。

为了验证您正确设置了加密规则，请用mysql社区客户端执行以下SQL，并确认看到数据加密的结果。
```sql
create table test.test (a int, b text, c timestamp);
insert into test.test values (1024, 'foobar', now());
select * from test.test;
```
预期的结果应该是一串乱码。

接下来，我们尝试用go客户端读取数据。

```go
package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/aliyun/alibabacloud-encdb-mysql-go-client"
)

func main() {

	db, err := sql.Open("encmysql", "user:password@tcp(host:port)/test?MEK=00112233445566778899aabbccddeeff&ENC_ALGO=SM4_128_CBC&parseTime=true")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM test")
	if err != nil {
		panic(err)
	}
	rows.Next()
	var a int
	var b string
	var c time.Time

	err = rows.Scan(&a, &b, &c)
	if err != nil {
		panic(err)
	}
	fmt.Printf("read data: %d %s %s\n", a, b, c.GoString())
}

```
预期的结果应该是：
```shell
$ go run .
# 日期视具体时间而定
read data: 1024 foobar time.Date(2024, time.May, 10, 9, 44, 11, 0, time.UTC)
```