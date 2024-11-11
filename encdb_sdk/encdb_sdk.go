package encdb_sdk

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/stretchr/objx"
)

type EncdbSDK struct {
	Cryptor  Cryptor
	Conn     *driver.Conn
	Is_polar bool
}

const ENCDB_SDK_VERSION = "1.2.15"

const (
	REQUEST_ID_MEK_PROVISION   int = 48
	REQUEST_ID_SERVER_INFO_GET     = 0
	REQUEST_ID_IMPORT_RULE         = 160
)

func (sdk *EncdbSDK) requestServer(msg string) (string, error) {
	var response []uint8
	rows, err := (*sdk.Conn).(driver.Queryer).Query("/*encoding_key*/SELECT encdb_process_message('"+msg+"')", nil)
	if err != nil {
		return "", err
	}
	var dest [1]driver.Value
	rows.Next(dest[:])
	rows.Close()
	response = dest[0].([]uint8)
	reponse_bytes, err := base64.StdEncoding.DecodeString(string(response))
	if err != nil {
		return "", err
	}
	encdb_response := objx.MustFromJSON(string(reponse_bytes))
	status := encdb_response.Get("status").Int()
	if status != 0 {
		panic("EncdbError: " + encdb_response.Get("body").Str())
	}
	return encdb_response.Get("body").Str(), nil
}

func (sdk *EncdbSDK) ImportRule(rule string) error {
	base64_rule := base64.StdEncoding.EncodeToString([]byte(rule))
	request := map[string]any{
		"request_type": REQUEST_ID_IMPORT_RULE,
		"enc_rule":     base64_rule,
		"version":      ENCDB_SDK_VERSION,
	}
	requestJson, _ := json.Marshal(request)
	_, err := sdk.requestServer(string(requestJson))
	return err
}

// return -1 if v1 < v2, 0 ==, 1 >
func compareVersions(v1 string, v2 string) int {
	v1parts := strings.Split(v1, ".")
	v2parts := strings.Split(v2, ".")

	maxLen := len(v1parts)
	if len(v2parts) > maxLen {
		maxLen = len(v2parts)
	}

	for i := 0; i < maxLen; i++ {
		var part1, part2 int
		if i < len(v1parts) {
			part1, _ = strconv.Atoi(v1parts[i])
		}
		if i < len(v2parts) {
			part2, _ = strconv.Atoi(v2parts[i])
		}

		if part1 > part2 {
			return 1
		} else if part1 < part2 {
			return -1
		}
	}

	return 0
}

func (sdk *EncdbSDK) GetServerInfo() {
	request := map[string]any{
		"request_type": REQUEST_ID_SERVER_INFO_GET,
		"version":      ENCDB_SDK_VERSION,
	}
	requestJson, _ := json.Marshal(request)
	body, err := sdk.requestServer(string(requestJson))
	if err != nil {
		panic(err)
	}

	server_info := objx.MustFromJSON(body)
	sdk.Cryptor.Server_cs = *FromString(server_info.Get("server_info.cipher_suite").Str())
	sdk.Cryptor.Server_puk = server_info.Get("server_info.public_key").Str()
	sdk.Cryptor.Server_puk_hash = server_info.Get("server_info.public_key_hash").Str()

	if !sdk.Is_polar {
		sdk.Cryptor.Server_version = RDS
	} else {
		encdb_version := server_info.Get("server_info.version").Str()
		if compareVersions(encdb_version, "1.1.14") == 0 {
			sdk.Cryptor.Server_version = POLAR_1_1_14
		} else {
			sdk.Cryptor.Server_version = POLAR_LAGACY
		}
	}
}

func (sdk *EncdbSDK) ProvisionMEK() error {
	if string(sdk.Cryptor.Algo) == "" {
		sdk.Cryptor.Algo = sdk.Cryptor.Server_cs.symmAlgo
	}
	if !SymmetricKeyValid(sdk.Cryptor.MEK, sdk.Cryptor.Algo) {
		return errors.New("Invalid mek " + hex.EncodeToString(sdk.Cryptor.MEK) + " with algo " + string(sdk.Cryptor.Algo))
	}
	if sdk.Cryptor.Server_puk_hash == "" || sdk.Cryptor.Server_puk == "" {
		return errors.New("server info not initialzed. Maybe you shoould call EncdbSDK.Init function")
	}
	request := map[string]any{
		"request_type":    REQUEST_ID_MEK_PROVISION,
		"cipher_suite":    sdk.Cryptor.Server_cs.ToString(),
		"public_key_hash": sdk.Cryptor.Server_puk_hash,
		"algorithm":       string(sdk.Cryptor.Algo),
		"version":         ENCDB_SDK_VERSION,
	}
	envelopeMek := map[string]any{
		"mek": base64.StdEncoding.EncodeToString(sdk.Cryptor.MEK),
	}
	envelopedMekJson, _ := json.Marshal(envelopeMek)
	envelopedMekJson, err := EnvelopeSeal(sdk.Cryptor.Server_cs, sdk.Cryptor.Server_puk, envelopedMekJson)
	request["envelope"] = base64.StdEncoding.EncodeToString(envelopedMekJson)
	requestJson, _ := json.Marshal(request)
	_, err = sdk.requestServer(string(requestJson))
	if err != nil {
		panic(err)
	}
	return err
}
