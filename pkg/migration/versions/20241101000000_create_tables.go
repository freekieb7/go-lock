package migration_version

import (
	"context"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/jwt/helper"
	"github.com/freekieb7/go-lock/pkg/migration"
	"github.com/freekieb7/go-lock/pkg/scope"
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

	jwks, err := helper.GenerateRsaJwks()
	if err != nil {
		panic(err)
	}

	resourceServer := model.ResourceServer{
		Id:                       uuid.New(),
		Name:                     "Auth Management API",
		Description:              "The Authentication Management API",
		Url:                      m.Settings.Host + "/api",
		IsSystem:                 true,
		SigningAlgorithm:         model.SigningAlgorithmRS256,
		AllowSkippingUserConsent: true,
		AllowOfflineAccess:       true,
		CreatedAt:                now,
		UpdatedAt:                now,
	}

	client := model.Client{
		Id:             m.Settings.ClientId,
		Secret:         m.Settings.ClientSecret,
		Name:           "Auth Management Application",
		Description:    "The Application Managing the Authentication Server",
		IsSystem:       true,
		IsConfidential: true,
		RedirectUrls:   m.Settings.Host + "/callback",
		LogoUrl:        "/public/logo.png",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	user := model.User{
		Id:            uuid.New(),
		Name:          "admin",
		Username:      "admin",
		Email:         "admin@localhost",
		PasswordHash:  passwordHash,
		Type:          model.UserTypeAdmin,
		Picture:       "",
		EmailVerified: true,
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
		Blocked:       false,
	}

	statements := []migration.Statement{
		{
			Query: `CREATE TABLE tbl_client (
				id TEXT NOT NULL,
				secret TEXT NOT NULL,
				name TEXT NOT NULL,
				description TEXT NOT NULL,
				is_system INT NOT NULL,
				is_confidential INTEGER NOT NULL,
				logo_url TEXT NOT NULL,
				redirect_urls TEXT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY(id)
	    	);`,
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
			);`,
		},
		{
			Query: `CREATE TABLE tbl_access_token (
				client_id TEXT NOT NULL,
				token TEXT NOT NULL,
				expiration_date NOT NULL,
				PRIMARY KEY(client_id, token),
				FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query: `CREATE TABLE tbl_jwks (
				id TEXT NOT NULL,
				public_key BLOB NOT NULL,
				private_key BLOB NOT NULL,
				public_key_modules BLOB NOT NULL,
				public_key_exponent BLOB NOT NULL,
				PRIMARY KEY(id)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_resource_server (
				id TEXT NOT NULL,
				url TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL,
				description INT NOT NULL,
				is_system INT NOT NULL,
				signing_algorithm TEXT NOT NULL,
				allow_skipping_user_consent INT NOT NULL,
				allow_offline_access INT NOT NULL,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY(id)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_user (
				id TEXT NOT NULL,
				name TEXT NOT NULL,
				username TEXT NOT NULL,
				email TEXT NOT NULL,
				password_hash TEXT NOT NULL,
				type TEXT NOT NULL,
				picture TEXT NOT NULL,
				email_verified INT NOT NULL,
				blocked INT NOT NULL,
				created_at INT NOT NULL,
				updated_at INT NOT NULL,
				PRIMARY KEY(id),
				UNIQUE(email),
				UNIQUE(username)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_session (
				id TEXT NOT NULL,
				data BLOB NOT NULL,
				PRIMARY KEY(id)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_refresh_token (
				id TEXT NOT NULL,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				resource_server_id TEXT NOT NULL,
				scope TEXT NOT NULL,
				created_at INT NOT NULL,
				expires_at INT NOT NULL,
				PRIMARY KEY (id, client_id)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_resource_server_scope (
				resource_server_id TEXT NOT NULL,
				value TEXT NOT NULL,
				description TEXT NOT NULL,
				PRIMARY KEY (resource_server_id, value),
				FOREIGN KEY (resource_server_id) REFERENCES tbl_resource_server (id) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query: `CREATE TABLE tbl_scopes_per_user (
				user_id TEXT NOT NULL,
				resource_server_id TEXT NOT NULL,
				resource_server_scope_value TEXT NOT NULL,
				PRIMARY KEY (user_id, resource_server_id, resource_server_scope_value),
				FOREIGN KEY (user_id) REFERENCES tbl_user(id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (resource_server_id, resource_server_scope_value) REFERENCES tbl_resource_server_scope(resource_server_id, value) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query:     `INSERT INTO tbl_resource_server (id, url, name, description, is_system, signing_algorithm, allow_skipping_user_consent, allow_offline_access, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?);`,
			Arguments: []any{resourceServer.Id, resourceServer.Url, resourceServer.Name, resourceServer.Description, resourceServer.IsSystem, resourceServer.SigningAlgorithm, resourceServer.AllowSkippingUserConsent, resourceServer.AllowOfflineAccess, resourceServer.CreatedAt, resourceServer.UpdatedAt},
		},
		{
			Query:     `INSERT INTO tbl_jwks (id, public_key, private_key, public_key_modules, public_key_exponent) VALUES (?,?,?,?,?);`,
			Arguments: []any{jwks.Id, jwks.PublicKey, jwks.PrivateKey, jwks.PublicKeyModules, jwks.PublicKeyExponent},
		},
		{
			Query:     `INSERT INTO tbl_client (id, secret, name, description, is_system, is_confidential, logo_url, redirect_urls, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?);`,
			Arguments: []any{client.Id, client.Secret, client.Name, client.Description, client.IsSystem, client.IsConfidential, client.LogoUrl, client.RedirectUrls, client.CreatedAt, client.UpdatedAt},
		},
		{
			Query:     `INSERT INTO tbl_user (id, name, username, email, password_hash, type, picture, email_verified, blocked, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);`,
			Arguments: []any{user.Id, user.Name, user.Username, user.Email, user.PasswordHash, user.Type, user.Picture, user.EmailVerified, user.Blocked, user.CreatedAt, user.UpdatedAt},
		},
		{
			Query: `INSERT INTO tbl_resource_server_scope (resource_server_id, value, description) VALUES (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?);`,
			Arguments: []any{
				resourceServer.Id, scope.CreateClients, "Create Clients",
				resourceServer.Id, scope.ReadClients, "Read Clients",
				resourceServer.Id, scope.UpdateClients, "Update Clients",
				resourceServer.Id, scope.DeleteClients, "Delete Clients",
				resourceServer.Id, scope.CreateResourceServers, "Create Resource Servers",
				resourceServer.Id, scope.ReadResourceServers, "Read Resource Servers",
				resourceServer.Id, scope.UpdateResourceServers, "Update Resource Servers",
				resourceServer.Id, scope.DeleteResourceServers, "Delete Resource Servers",
				resourceServer.Id, scope.CreateUsers, "Create Users",
				resourceServer.Id, scope.ReadUsers, "Read Users",
				resourceServer.Id, scope.UpdateUsers, "Update Users",
				resourceServer.Id, scope.DeleteUsers, "Delete Users",
			},
		},
		{
			Query: `INSERT INTO tbl_scopes_per_user (user_id, resource_server_id, resource_server_scope_value) VALUES (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?), (?,?,?);`,
			Arguments: []any{
				user.Id, resourceServer.Id, scope.CreateClients,
				user.Id, resourceServer.Id, scope.ReadClients,
				user.Id, resourceServer.Id, scope.UpdateClients,
				user.Id, resourceServer.Id, scope.DeleteClients,
				user.Id, resourceServer.Id, scope.CreateResourceServers,
				user.Id, resourceServer.Id, scope.ReadResourceServers,
				user.Id, resourceServer.Id, scope.UpdateResourceServers,
				user.Id, resourceServer.Id, scope.DeleteResourceServers,
				user.Id, resourceServer.Id, scope.CreateUsers,
				user.Id, resourceServer.Id, scope.ReadUsers,
				user.Id, resourceServer.Id, scope.UpdateUsers,
				user.Id, resourceServer.Id, scope.DeleteUsers,
			},
		},
	}

	return statements
}

func (*migration20241101000000) Down() []migration.Statement {

	return []migration.Statement{
		{
			Query: `DROP TABLE tbl_scopes_per_user;`,
		},
		{
			Query: `DROP TABLE tbl_resource_server_scope;`,
		},
		{
			Query: `DROP TABLE tbl_refresh_token;`,
		},
		{
			Query: `DROP TABLE tbl_session;`,
		},
		{
			Query: `DROP TABLE tbl_user;`,
		},
		{
			Query: `DROP TABLE tbl_resource_server;`,
		},
		{
			Query: `DROP TABLE tbl_jwks;`,
		},
		{
			Query: `DROP TABLE tbl_access_token;`,
		},
		{
			Query: `DROP TABLE tbl_authorization_code;`,
		},
		{
			Query: `DROP TABLE tbl_client;`,
		},
	}
}
