package api

import (
	"log"

	"github.com/SudTechnology/sud-mgp-auth-go/jwt_utils"
)

var (
	// twoHourMinExpire 2小时有效时间
	twoHourMinExpire int64 = 2 * 60 * 60 * 1000

	//halfHourMinExpire 30分钟有效时间
	halfHourMinExpire int64 = 30 * 60 * 1000
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

func (client *SudMGPAuth) GetCode(uid string, expireDuration int64) *SudCode {
	exp := halfHourMinExpire
	if expireDuration > exp {
		exp = expireDuration
	}
	return client.getBaseCode(uid, exp)
}

func (client *SudMGPAuth) GetCodeByDefaultDuration(uid string) *SudCode {
	return client.getBaseCode(uid, twoHourMinExpire)
}

func (client *SudMGPAuth) getBaseCode(uid string, expireDuration int64) *SudCode {
	// 实例化UserClaims，传入参数
	userClaims := &jwt_utils.UserClaims{
		AppID: client.AppID,
		Uid:   uid,
	}
	token, exp, err := jwt_utils.GetToken(userClaims, client.AppSecret, expireDuration)
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

func (client *SudMGPAuth) GetSSToken(uid string, expireDuration int64) *SudSSToken {
	exp := twoHourMinExpire
	if expireDuration > exp {
		exp = expireDuration
	}
	return client.getBaseToken(uid, exp)
}

func (client *SudMGPAuth) GetSSTokenByDefaultDuration(uid string) *SudSSToken {
	return client.getBaseToken(uid, twoHourMinExpire)
}

func (client *SudMGPAuth) getBaseToken(uid string, expireDuration int64) *SudSSToken {
	// 实例化UserClaims，传入参数
	userClaims := &jwt_utils.UserClaims{
		AppID: client.AppID,
		Uid:   uid,
	}

	token, exp, err := jwt_utils.GetToken(userClaims, client.AppSecret, expireDuration)
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
	userClaims, err, errorCode := jwt_utils.ParseToken(code, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		resp.SdkErrorCode = errorCode
		return resp
	}
	if errorCode != 0 {
		log.Printf("errorCode:%+v \n", errorCode)
		resp.SdkErrorCode = errorCode
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
	userClaims, err, sdkErrorCode := jwt_utils.ParseToken(ssToken, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		resp.SdkErrorCode = sdkErrorCode
		return resp
	}
	if sdkErrorCode != 0 {
		log.Printf("errorCode:%+v \n", sdkErrorCode)
		resp.SdkErrorCode = sdkErrorCode
		return resp
	}

	resp = &SudUid{
		Uid:       userClaims.Uid,
		IsSuccess: true,
	}
	log.Printf("resp:%+v \n", resp)
	return resp
}

func (client *SudMGPAuth) VerifyCode(code string) int32 {
	_, err, sdkErrorCode := jwt_utils.ParseToken(code, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return sdkErrorCode
	}
	return sdkErrorCode
}

func (client *SudMGPAuth) VerifySSToken(token string) int32 {
	_, err, errCode := jwt_utils.ParseToken(token, client.AppSecret)
	if err != nil {
		log.Printf("err:%+v \n", err)
		return errCode
	}
	return errCode
}
