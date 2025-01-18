package migration_version

import (
	"context"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/migration"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	migration.Register(&migration20241101000000{
		settings.New(context.TODO()),
	})
}

type migration20241101000000 struct {
	Settings *settings.Settings
}

func (*migration20241101000000) Identifier() string {
	return "20241101000000_create_tables"
}

func (m *migration20241101000000) Up() []migration.Statement {
	now := time.Now().Unix()

	jwks, err := jwt.GenerateRsaJwks()
	if err != nil {
		panic(err)
	}

	resourceServer := model.ResourceServer{
		Id:                       random.NewString(32),
		Name:                     "Auth Management API",
		Url:                      m.Settings.Host + "/api",
		Type:                     model.ResourceServerTypeSystemServer,
		SigningAlgorithm:         model.SigningAlgorithmRS256,
		Scopes:                   "",
		AllowSkippingUserConsent: true,
		CreatedAt:                now,
		UpdatedAt:                now,
		DeletedAt:                0,
	}

	client := model.Client{
		Id:             m.Settings.ClientId,
		Secret:         m.Settings.ClientSecret,
		Name:           "Auth Management Application",
		Type:           model.ClientTypeSystem,
		IsConfidential: true,
		RedirectUrls:   m.Settings.Host + "/callback",
		CreatedAt:      now,
		UpdatedAt:      now,
		DeletedAt:      0,
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	user := model.User{
		Id:           uuid.New(),
		Name:         "admin",
		Username:     "admin",
		Email:        "admin@localhost",
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
		DeletedAt:    0,
	}

	statements := []migration.Statement{
		{
			Query: `CREATE TABLE tbl_client (
	        id TEXT NOT NULL,
	        secret TEXT NOT NULL,
	        name TEXT NOT NULL,
			type TEXT NOT NULL,
	        is_confidential INTEGER NOT NULL,
			redirect_urls TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			deleted_at TEXT NOT NULL,
	        PRIMARY KEY(id)
	    	);`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_authorization_code (
	        client_id TEXT NOT NULL,
	        code TEXT NOT NULL,
	        audience TEXT NOT NULL,
			user_id BLOB NOT NULL,
			scope TEXT NOT NULL,
			code_challenge TEXT,
	        PRIMARY KEY(client_id, code),
	        FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_access_token (
	        client_id TEXT NOT NULL,
	        token TEXT NOT NULL,
	        expiration_date NOT NULL,
	        PRIMARY KEY(client_id, token),
	        FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_jwks (
	        id TEXT NOT NULL,
	        public_key BLOB NOT NULL,
	        private_key BLOB NOT NULL,
	        public_key_modules BLOB NOT NULL,
	        public_key_exponent BLOB NOT NULL,
	        PRIMARY KEY(id)
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_resource_server (
	        id TEXT NOT NULL,
	        url TEXT NOT NULL UNIQUE,
	        name TEXT NOT NULL,
	        signing_algorithm TEXT NOT NULL,
			scopes TEXT NOT NULL,
			allow_skipping_user_consent INT NOT NULL,
			type TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			deleted_at TEXT NOT NULL,
			PRIMARY KEY(id)
	    );`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_user (
	        id TEXT NOT NULL,
			name TEXT NOT NULL,
			username TEXT NOT NULL,
	        email TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			created_at INT NOT NULL,
			updated_at INT NOT NULL,
			deleted_at INT NOT NULL,
	        PRIMARY KEY(id),
	        UNIQUE(email)
	    );`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_session (
	        id TEXT NOT NULL,
	        data BLOB NOT NULL,
	        PRIMARY KEY(id)
	    );`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE tbl_refresh_token (
			id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			audience TEXT NOT NULL,
			scope TEXT NOT NULL,
			created_at INT NOT NULL,
			expires_at INT NOT NULL,
			PRIMARY KEY (id, client_id)
		);`,
			Arguments: []any{},
		},
		{
			Query:     `INSERT INTO tbl_resource_server (id, url, name, type, signing_algorithm, scopes, allow_skipping_user_consent, created_at, updated_at, deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?);`,
			Arguments: []any{resourceServer.Id, resourceServer.Url, resourceServer.Name, resourceServer.Type, resourceServer.SigningAlgorithm, resourceServer.Scopes, resourceServer.AllowSkippingUserConsent, resourceServer.CreatedAt, resourceServer.UpdatedAt, resourceServer.DeletedAt},
		},
		{
			Query:     `INSERT INTO tbl_jwks (id, public_key, private_key, public_key_modules, public_key_exponent) VALUES (?,?,?,?,?);`,
			Arguments: []any{jwks.Id, jwks.PublicKey, jwks.PrivateKey, jwks.PublicKeyModules, jwks.PublicKeyExponent},
		},
		{
			Query:     `INSERT INTO tbl_client (id, secret, name, type, is_confidential, redirect_urls, created_at, updated_at, deleted_at) VALUES(?,?,?,?,?,?,?,?,?);`,
			Arguments: []any{client.Id, client.Secret, client.Name, client.Type, client.IsConfidential, client.RedirectUrls, client.CreatedAt, client.UpdatedAt, client.DeletedAt},
		},
		{
			Query:     `INSERT INTO tbl_user (id, name, username, email, password_hash, created_at, updated_at, deleted_at) VALUES (?,?,?,?,?,?,?,?);`,
			Arguments: []any{user.Id, user.Name, user.Username, user.Email, user.PasswordHash, user.CreatedAt, user.UpdatedAt, user.DeletedAt},
		},
	}

	return statements
}

func (*migration20241101000000) Down() []migration.Statement {

	return []migration.Statement{
		{
			Query:     `DROP TABLE tbl_refresh_token;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_session;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_user;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_resource_server;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_jwks;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_access_token;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_authorization_code;`,
			Arguments: []any{},
		},
		{
			Query:     `DROP TABLE tbl_client;`,
			Arguments: []any{},
		},
	}
}
