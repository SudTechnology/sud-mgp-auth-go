package api

import (
	"log"

	"github.com/SudTechnology/sud-mgp-auth-go/jwt_utils"
)

type SudMGPAuth struct {
	AppID     string
	AppSecret string
}

func NewSudMGPAuth(appID string, appSecret string) *SudMGPAuth {
	client := &SudMGPAuth{
		AppID:     appID,
		AppSecret: appSecret,
	}
	return client
}

func (client *SudMGPAuth) GetCode(uid string) *SudCode {
	// 实例化UserClaims，传入参数
	userClaims := &jwt_utils.UserClaims{
		AppID: client.AppID,
		Uid:   uid,
	}

	token, exp, err := jwt_utils.GetToken(userClaims, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
	}

	resp := &SudCode{
		Code:       token,
		ExpireDate: exp,
	}
	log.Printf("resp:%+v \n", resp)
	return resp
}

func (client *SudMGPAuth) GetSSToken(uid string) *SudSSToken {
	// 实例化UserClaims，传入参数
	userClaims := &jwt_utils.UserClaims{
		AppID: client.AppID,
		Uid:   uid,
	}

	token, exp, err := jwt_utils.GetToken(userClaims, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
	}

	resp := &SudSSToken{
		Token:      token,
		ExpireDate: exp,
	}
	log.Printf("resp:%+v \n", resp)
	return resp
}

func (client *SudMGPAuth) GetUidByCode(code string) *SudUid {
	resp := &SudUid{
		IsSuccess: false,
	}
	userClaims, err := jwt_utils.ParseToken(code, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return resp
	}

	resp = &SudUid{
		Uid:       userClaims.Uid,
		IsSuccess: true,
	}
	log.Printf("resp:%+v \n", resp)
	return resp
}

func (client *SudMGPAuth) GetUidBySSToken(ssToken string) *SudUid {
	resp := &SudUid{
		IsSuccess: false,
	}
	userClaims, err := jwt_utils.ParseToken(ssToken, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return resp
	}

	resp = &SudUid{
		Uid:       userClaims.Uid,
		IsSuccess: true,
	}
	log.Printf("resp:%+v \n", resp)
	return resp
}

func (client *SudMGPAuth) VerifyCode(code string) bool {
	_, err := jwt_utils.ParseToken(code, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return false
	}
	return true
}

func (client *SudMGPAuth) VerifySSToken(token string) bool {
	_, err := jwt_utils.ParseToken(token, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return false
	}
	return true
}
