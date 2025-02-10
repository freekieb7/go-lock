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

	permissions := []model.Permission{
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
			Query: `CREATE TABLE tbl_permission (
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
			Query: `CREATE TABLE tbl_permission_per_user (
				user_id TEXT NOT NULL,
				permission_id TEXT NOT NULL,
				PRIMARY KEY (user_id, permission_id),
				FOREIGN KEY (user_id) REFERENCES tbl_user (id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (permission_id) REFERENCES tbl_permission (id) ON UPDATE CASCADE ON DELETE CASCADE
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
			Query: `CREATE TABLE tbl_permission_per_role (
				role_id TEXT NOT NULL,
				permission_id TEXT NOT NULL,
				PRIMARY KEY (role_id, permission_id),
				FOREIGN KEY (role_id) REFERENCES tbl_role (id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (permission_id) REFERENCES tbl_permission (id) ON UPDATE CASCADE ON DELETE CASCADE
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
			Query: `INSERT INTO tbl_permission (id, resource_server_id, value, description) VALUES (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?), (?,?,?,?);`,
			Arguments: []any{
				permissions[0].Id, permissions[0].ResourceServerId, permissions[0].Value, permissions[0].Description,
				permissions[1].Id, permissions[1].ResourceServerId, permissions[1].Value, permissions[1].Description,
				permissions[2].Id, permissions[2].ResourceServerId, permissions[2].Value, permissions[2].Description,
				permissions[3].Id, permissions[3].ResourceServerId, permissions[3].Value, permissions[3].Description,
				permissions[4].Id, permissions[4].ResourceServerId, permissions[4].Value, permissions[4].Description,
				permissions[5].Id, permissions[5].ResourceServerId, permissions[5].Value, permissions[5].Description,
				permissions[6].Id, permissions[6].ResourceServerId, permissions[6].Value, permissions[6].Description,
				permissions[7].Id, permissions[7].ResourceServerId, permissions[7].Value, permissions[7].Description,
				permissions[8].Id, permissions[8].ResourceServerId, permissions[8].Value, permissions[8].Description,
				permissions[9].Id, permissions[9].ResourceServerId, permissions[9].Value, permissions[9].Description,
				permissions[10].Id, permissions[10].ResourceServerId, permissions[10].Value, permissions[10].Description,
				permissions[11].Id, permissions[11].ResourceServerId, permissions[11].Value, permissions[11].Description,
			},
		},
		{
			Query: `INSERT INTO tbl_permission_per_user (user_id, permission_id) VALUES (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?), (?,?);`,
			Arguments: []any{
				user.Id, permissions[0].Id,
				user.Id, permissions[1].Id,
				user.Id, permissions[2].Id,
				user.Id, permissions[3].Id,
				user.Id, permissions[4].Id,
				user.Id, permissions[5].Id,
				user.Id, permissions[6].Id,
				user.Id, permissions[7].Id,
				user.Id, permissions[8].Id,
				user.Id, permissions[9].Id,
				user.Id, permissions[10].Id,
				user.Id, permissions[11].Id,
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
			Query: `DROP TABLE tbl_permission_per_user;`,
		},
		{
			Query: `DROP TABLE tbl_permission;`,
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
