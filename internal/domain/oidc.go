package domain

type OIDCToken struct {
	Username         string
	IdPID            string
	Email            string
	GivenName        string
	FamilyName       string
	EnrollmentStatus string
}
