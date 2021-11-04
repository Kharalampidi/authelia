package schema

import "time"

// LDAPAuthenticationBackendConfiguration represents the configuration related to LDAP server.
type LDAPAuthenticationBackendConfiguration struct {
	Implementation string        `koanf:"implementation"`
	URL            string        `koanf:"url"`
	Timeout        time.Duration `koanf:"timeout"`
	StartTLS       bool          `koanf:"start_tls"`
	TLS            *TLSConfig    `koanf:"tls"`

	BaseDN string `koanf:"base_dn"`

	AdditionalUsersDN string `koanf:"additional_users_dn"`
	UsersFilter       string `koanf:"users_filter"`

	AdditionalGroupsDN string `koanf:"additional_groups_dn"`
	GroupsFilter       string `koanf:"groups_filter"`

	GroupNameAttribute   string `koanf:"group_name_attribute"`
	UsernameAttribute    string `koanf:"username_attribute"`
	MailAttribute        string `koanf:"mail_attribute"`
	DisplayNameAttribute string `koanf:"display_name_attribute"`

	User     string `koanf:"user"`
	Password string `koanf:"password"`
}

// FileAuthenticationBackendConfiguration represents the configuration related to file-based backend.
type FileAuthenticationBackendConfiguration struct {
	Path     string                 `koanf:"path"`
	Password *PasswordConfiguration `koanf:"password"`
}

type MysqlAuthenticationBackendConfiguration struct {
	Connection *MysqlAuthenticationBackendConnectionConfiguration `koanf:"connection"`
	Password   *PasswordConfiguration                             `koanf:"password"`
}

type MysqlAuthenticationBackendConnectionConfiguration struct {
	Host     string        `koanf:"host"`
	Port     int           `koanf:"port"`
	Database string        `koanf:"database"`
	Username string        `koanf:"username"`
	Password string        `koanf:"password"`
	Timeout  time.Duration `koanf:"timeout"`
}

// PasswordConfiguration represents the configuration related to password hashing.
type PasswordConfiguration struct {
	Iterations  int    `koanf:"iterations"`
	KeyLength   int    `koanf:"key_length"`
	SaltLength  int    `koanf:"salt_length"`
	Algorithm   string `mapstrucutre:"algorithm"`
	Memory      int    `koanf:"memory"`
	Parallelism int    `koanf:"parallelism"`
}

// AuthenticationBackendConfiguration represents the configuration related to the authentication backend.
type AuthenticationBackendConfiguration struct {
	DisableResetPassword bool                                     `koanf:"disable_reset_password"`
	RefreshInterval      string                                   `koanf:"refresh_interval"`
	LDAP                 *LDAPAuthenticationBackendConfiguration  `koanf:"ldap"`
	File                 *FileAuthenticationBackendConfiguration  `koanf:"file"`
	MySQL                *MysqlAuthenticationBackendConfiguration `koanf:"mysql"`
}

// DefaultPasswordConfiguration represents the default configuration related to Argon2id hashing.
var DefaultPasswordConfiguration = PasswordConfiguration{
	Iterations:  1,
	KeyLength:   32,
	SaltLength:  16,
	Algorithm:   argon2id,
	Memory:      64,
	Parallelism: 8,
}

// DefaultCIPasswordConfiguration represents the default configuration related to Argon2id hashing for CI.
var DefaultCIPasswordConfiguration = PasswordConfiguration{
	Iterations:  1,
	KeyLength:   32,
	SaltLength:  16,
	Algorithm:   argon2id,
	Memory:      64,
	Parallelism: 8,
}

// DefaultPasswordSHA512Configuration represents the default configuration related to SHA512 hashing.
var DefaultPasswordSHA512Configuration = PasswordConfiguration{
	Iterations: 50000,
	SaltLength: 16,
	Algorithm:  "sha512",
}

// DefaultLDAPAuthenticationBackendConfiguration represents the default LDAP config.
var DefaultLDAPAuthenticationBackendConfiguration = LDAPAuthenticationBackendConfiguration{
	Implementation:       LDAPImplementationCustom,
	UsernameAttribute:    "uid",
	MailAttribute:        "mail",
	DisplayNameAttribute: "displayName",
	GroupNameAttribute:   "cn",
	Timeout:              time.Second * 5,
	TLS: &TLSConfig{
		MinimumVersion: "TLS1.2",
	},
}

// DefaultLDAPAuthenticationBackendImplementationActiveDirectoryConfiguration represents the default LDAP config for the MSAD Implementation.
var DefaultLDAPAuthenticationBackendImplementationActiveDirectoryConfiguration = LDAPAuthenticationBackendConfiguration{
	UsersFilter:          "(&(|({username_attribute}={input})({mail_attribute}={input}))(sAMAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(pwdLastSet=0)))",
	UsernameAttribute:    "sAMAccountName",
	MailAttribute:        "mail",
	DisplayNameAttribute: "displayName",
	GroupsFilter:         "(&(member={dn})(objectClass=group))",
	GroupNameAttribute:   "cn",
}
