package api

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

func TestGetCode(t *testing.T) {
	client := NewSudMGPAuth(appID, appSecret)

	// 生成token和有效期
	sudUID := client.GetCode(uid, 60*60*1000)
	t.Logf("GetCode code:%+v \n", sudUID.Code)
	t.Logf("GetCode exp:%+v \n", sudUID.ExpireDate)

	useSudUID := client.GetCodeByDefaultDuration(uid)
	t.Logf("GetCodeByDefaultDuration code:%+v \n", useSudUID.Code)
	t.Logf("GetCodeByDefaultDuration exp:%+v \n", useSudUID.ExpireDate)
}

func TestGetSstoken(t *testing.T) {
	client := NewSudMGPAuth(appID, appSecret)

	// 生成token和有效期
	sudUID := client.GetSSToken(uid, 3*60*60*1000)
	t.Logf("GetSSToken code:%+v \n", sudUID.Token)
	t.Logf("GetSSToken exp:%+v \n", sudUID.ExpireDate)

	useSudUID := client.GetSSTokenByDefaultDuration(uid)
	t.Logf("GetSSTokenByDefaultDuration code:%+v \n", useSudUID.Token)
	t.Logf("GetSSTokenByDefaultDuration exp:%+v \n", useSudUID.ExpireDate)
}
