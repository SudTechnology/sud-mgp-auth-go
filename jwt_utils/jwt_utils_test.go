package jwt_utils

import (
	"testing"
)

const (
	appID     = "1461564080052506636"
	appSecret = "xJL0HU9ailVSGInqPyNK3Ev3qNHReRbR"
)

const (
	uid = "123"
)

func TestGetToken(t *testing.T) {
	// 实例化UserClaims，传入参数
	userClaims := &UserClaims{
		AppID: appID,
		Uid:   uid,
	}

	// 生成token和有效期
	token, exp, err := GetToken(userClaims, appSecret, 0)
	if err != nil {
		t.Logf("err:%+v \n", err)
	}
	t.Logf("token:%+v \n", token)
	t.Logf("exp:%+v \n", exp)
}

func TestParseToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxMjMiLCJhcHBfaWQiOiIxNDYxNTY0MDgwMDUyNTA2NjM2IiwiZXhwIjoxNjM4OTc4NDQ1fQ.BEhJHNbGsd9hs_oK6IPg0D1A46cKH3mTf3UMTSjlcTk"
	userClaims, err, sdkErrorCode := ParseToken(token, appSecret)
	if err != nil {
		t.Logf("err:%+v \n", err)
	}

	if sdkErrorCode != 0 {
		t.Logf("sdkErrorCode:%+v \n", sdkErrorCode)
	}
	t.Logf("userClaims:%+v \n", userClaims)
}

