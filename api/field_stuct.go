package api

type SudCode struct {
	Code       string `json:"code"`
	ExpireDate int64  `json:"expire_date"`
}

type SudSSToken struct {
	Token      string `json:"ss_token"`
	ExpireDate int64  `json:"expire_date"`
}

type SudUid struct {
	Uid       string `json:"uid"`
	IsSuccess bool   `json:"is_success"`
}
