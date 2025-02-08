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

	scopes := []model.Scope{
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.CreateClients,
			Description:      "Create Clients",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.ReadClients,
			Description:      "Read Clients",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.UpdateClients,
			Description:      "Update Clients",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.DeleteClients,
			Description:      "Delete Clients",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.CreateUsers,
			Description:      "Create Users",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.ReadUsers,
			Description:      "Read Users",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.UpdateUsers,
			Description:      "Update Users",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.DeleteUsers,
			Description:      "Delete Users",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.CreateResourceServers,
			Description:      "Create ResourceServers",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.ReadResourceServers,
			Description:      "Read ResourceServers",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.UpdateResourceServers,
			Description:      "Update ResourceServers",
		},
		{
			Id:               uuid.New(),
			ResourceServerId: resourceServer.Id,
			Value:            scope.DeleteResourceServers,
			Description:      "Delete ResourceServers",
		},
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
			Query: `CREATE TABLE tbl_scope (
				id TEXT NOT NULL,
				resource_server_id TEXT NOT NULL,
				value TEXT NOT NULL,
				description TEXT NOT NULL,
				PRIMARY KEY (id),
				UNIQUE (resource_server_id, value),
				FOREIGN KEY (resource_server_id) REFERENCES tbl_resource_server (id) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query: `CREATE TABLE tbl_scope_per_user (
				user_id TEXT NOT NULL,
				scope_id TEXT NOT NULL,
				PRIMARY KEY (user_id, scope_id),
				FOREIGN KEY (user_id) REFERENCES tbl_user (id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (scope_id) REFERENCES tbl_scope (id) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query: `CREATE TABLE tbl_role (
				id TEXT NOT NULL,
				name TEXT NOT NULL,
				description TEXT NOT NULL, 
				PRIMARY KEY (id),
				UNIQUE (name)
			);`,
		},
		{
			Query: `CREATE TABLE tbl_scope_per_role (
				role_id TEXT NOT NULL,
				scope_id TEXT NOT NULL,
				PRIMARY KEY (role_id, scope_id),
				FOREIGN KEY (role_id) REFERENCES tbl_role (id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (scope_id) REFERENCES tbl_scope (id) ON UPDATE CASCADE ON DELETE CASCADE
			);`,
		},
		{
			Query: `CREATE TABLE tbl_role_per_user (
				user_id TEXT NOT NULL,
				role_id TEXT NOT NULL,
				PRIMARY KEY (user_id, role_id),
				FOREIGN KEY (user_id) REFERENCES tbl_user (id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (role_id) REFERENCES tbl_role (id) ON UPDATE CASCADE ON DELETE CASCADE
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
			Query: `INSERT INTO tbl_scope (id, resource_server_id, value, description) VALUES (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?);`,
			Arguments: []any{
				scopes[0].Id, scopes[0].ResourceServerId, scopes[0].Value, scopes[0].Description,
				scopes[1].Id, scopes[1].ResourceServerId, scopes[1].Value, scopes[1].Description,
				scopes[2].Id, scopes[2].ResourceServerId, scopes[2].Value, scopes[2].Description,
				scopes[3].Id, scopes[3].ResourceServerId, scopes[3].Value, scopes[3].Description,
				scopes[4].Id, scopes[4].ResourceServerId, scopes[4].Value, scopes[4].Description,
				scopes[5].Id, scopes[5].ResourceServerId, scopes[5].Value, scopes[5].Description,
				scopes[6].Id, scopes[6].ResourceServerId, scopes[6].Value, scopes[6].Description,
				scopes[7].Id, scopes[7].ResourceServerId, scopes[7].Value, scopes[7].Description,
				scopes[8].Id, scopes[8].ResourceServerId, scopes[8].Value, scopes[8].Description,
				scopes[9].Id, scopes[9].ResourceServerId, scopes[9].Value, scopes[9].Description,
				scopes[10].Id, scopes[10].ResourceServerId, scopes[10].Value, scopes[10].Description,
				scopes[11].Id, scopes[11].ResourceServerId, scopes[11].Value, scopes[11].Description,
			},
		},
		{
			Query: `INSERT INTO tbl_scope_per_user (user_id, scope_id) VALUES (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?);`,
			Arguments: []any{
				user.Id, scopes[0].Id,
				user.Id, scopes[1].Id,
				user.Id, scopes[2].Id,
				user.Id, scopes[3].Id,
				user.Id, scopes[4].Id,
				user.Id, scopes[5].Id,
				user.Id, scopes[6].Id,
				user.Id, scopes[7].Id,
				user.Id, scopes[8].Id,
				user.Id, scopes[9].Id,
				user.Id, scopes[10].Id,
				user.Id, scopes[11].Id,
			},
		},
	}

	return statements
}

func (*migration20241101000000) Down() []migration.Statement {

	return []migration.Statement{
		{
			Query: `DROP TABLE tbl_role_per_user`,
		},
		{
			Query: `DROP TABLE tbl_role`,
		},
		{
			Query: `DROP TABLE tbl_scope_per_user;`,
		},
		{
			Query: `DROP TABLE tbl_scope;`,
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
