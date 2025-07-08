package models

// User model contains user data like GUID, email, IP and refresh token
type User struct {
	GUID string `json:"guid" db:"guid"`
}

type TokenRow struct {
	JTI          string `db:"jti"`
	RefreshToken string `db:"refresh_token"`
	IP           string `db:"ip"`
	UserAgent    string `db:"user_agent"`
	GUID         string `db:"user_guid"`
}
