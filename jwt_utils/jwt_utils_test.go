package jwt_utils

import (
	"testing"
)

var (
	appId     = "appId123"
	appSecret = "243223ffslsfsldfl412fdsfsdf"

	uid = "1234"
)

func TestGetToken(t *testing.T) {
	// 实例化UserClaims，传入参数
	userClaims := &UserClaims{
		AppID: appId,
		Uid:   uid,
	}

	// 生成token和有效期（有效期默认2小时）
	token, exp, err := GetToken(userClaims, appSecret)
	if err != nil {
		t.Logf("err:%+v \n", err)
	}
	t.Logf("token:%+v,exp:%+v \n", token, exp)
}

func TestParseToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxMjM0IiwiYXBwX2lkIjoiYXBwSWQxMjMiLCJleHAiOjE2MzE4NTcyMzl9.RKC7q5UNuUld17vncEDAvJvwuVZ9B23sclitXp2C7qM"
	userClaims, err := ParseToken(token, appSecret)
	if err != nil {
		t.Logf("err:%+v \n", err)
	}
	t.Logf("userClaims:%+v \n", userClaims)
}

func TestUpdateToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIxMjM0IiwiYXBwX2lkIjoiYXBwSWQxMjMiLCJleHAiOjE2MzE4NTUxMjN9.FeLqEK7Nz-5gq6l8FTkdXcGdPJgLgdY98tfc4r7tVB0"
	newToken, exp, err := UpdateToken(token, appSecret)
	if err != nil {
		t.Logf("err:%+v \n", err)
	}
	t.Logf("newToken:%+v,exp:%+v \n", newToken, exp)
}
