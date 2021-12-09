package jwt_utils

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	/**
	 * 成功
	 */
	tokenSuccess = 0
	/**
	 * Token创建失败
	 */
	tokenCreateFailed = 1001
	/**
	 * Token校验失败（算法，签名错误）
	 */
	tokenVerifyFailed = 1002
	/**
	 * Token解析失败
	 */
	tokenDecodeFailed = 1003
	/**
	 * Token非法（携带的Claim错误）
	 */
	tokenInvalid = 1004
	/**
	 * Token过期
	 */
	tokenExpired = 1005
	/**
	 * 未知错误
	 */
	undefine = 9999
)

//UserClaims 用户信息类，作为生成token的参数
type UserClaims struct {
	Uid   string `json:"uid"`
	AppID string `json:"app_id"`
	//jwt-go提供的标准claim
	jwt.StandardClaims
}

var (
	//token有效时间（纳秒）
	effectTime = 2 * time.Hour
)

// GetToken 生成token
func GetToken(claims *UserClaims, secret string, expireDuration int64) (string, int64, error) {
	exp := time.Now().Add(effectTime).Unix()

	if expireDuration > effectTime.Milliseconds() {
		addExp := time.Duration(expireDuration) * time.Millisecond
		exp = time.Now().Add(addExp).Unix()
	}

	claims.ExpiresAt = exp
	//生成token
	sign, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return "", exp, err
	}

	clientExp := exp * 1000
	return sign, clientExp, nil
}

// ParseToken 解析Token
func ParseToken(tokenString string, secret string) (*UserClaims, error, int32) {
	//解析token
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %+v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	v, validOk := err.(*jwt.ValidationError)
	if validOk && v.Errors == jwt.ValidationErrorExpired {
		return nil, fmt.Errorf("token is tokenExpired. token:%+v,err:%+v", tokenString, err), tokenExpired
	}

	if err != nil {
		return nil, fmt.Errorf("token check error. token:%+v, err:%+v", tokenString, err), tokenVerifyFailed
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is valid. token:%+v, valid:%+v", tokenString, token.Valid), tokenVerifyFailed
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("claims is valid. token:%+v, valid:%+v", tokenString, token.Valid), tokenDecodeFailed
	}

	return claims, nil, tokenSuccess
}

// UpdateToken 更新token
func UpdateToken(tokenString string, secret string) (string, int64, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %+v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", 0, err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return "", 0, fmt.Errorf("token is valid. token:%+v, valid:%+v", tokenString, token.Valid)
	}

	newToken, exp, err := GetToken(claims, secret, 0)
	if err != nil {
		return "", 0, err
	}
	return newToken, exp, nil
}
