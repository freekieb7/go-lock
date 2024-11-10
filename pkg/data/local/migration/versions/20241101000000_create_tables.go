package migration_version

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"log"

	"github.com/freekieb7/go-lock/pkg/data/local/migration"
	"github.com/freekieb7/go-lock/pkg/data/local/model"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
)

type migrationCreateTables struct {
	Settings *settings.Settings
}

func NewMigrationCreateTables(settings *settings.Settings) migration.Migration {
	return &migrationCreateTables{
		settings,
	}
}

func (migration *migrationCreateTables) Identifier() string {
	return "20241101000000_create_tables"
}

func (migration *migrationCreateTables) Up() (string, []any) {
	api := model.Api{
		Id:               random.NewString(32),
		Name:             migration.Settings.Name,
		Uri:              migration.Settings.Host,
		SigningAlgorithm: model.SigningAlgorithmRS256,
	}

	// generate key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privatekey)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	var privateKeyBuff bytes.Buffer
	err = pem.Encode(&privateKeyBuff, privateKeyBlock)
	if err != nil {
		log.Fatal(err)
	}

	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	var publicKeyBuff bytes.Buffer
	err = pem.Encode(&publicKeyBuff, publicKeyBlock)
	if err != nil {
		log.Fatal(err)
	}

	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(publickey.E))
	bs = bs[1:] // drop most significant byte - leaving least-significant 3-bytes

	jwks := model.Jwks{
		Id:                random.NewString(24),
		PublicKey:         publicKeyBuff.Bytes(),
		PrivateKey:        privateKeyBuff.Bytes(),
		PublicKeyModules:  publickey.N.Bytes(),
		PublicKeyExponent: bs,
	}

	return `
        CREATE TABLE IF NOT EXISTS tbl_client (
            id TEXT NOT NULL,
            secret BLOB NOT NULL,
            name TEXT NOT NULL,
            confidential INTEGER NOT NULL DEFAULT FALSE,
            PRIMARY KEY(id)
        );

        CREATE TABLE IF NOT EXISTS tbl_redirect_uri (
            client_id TEXT NOT NULL,
            uri TEXT NOT NULL,
            FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tbl_authorization_code (
            client_id TEXT NOT NULL,
            code TEXT NOT NULL,
            audience TEXT NOT NULL,
			scope TEXT NOT NULL,
			code_challenge TEXT,
            PRIMARY KEY(client_id, code),
            FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tbl_access_token (
            client_id TEXT NOT NULL,
            token TEXT NOT NULL,
            expiration_date NOT NULL,
            PRIMARY KEY(client_id, token),
            FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tbl_jwks (
            id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL,
            public_key_modules BLOB NOT NULL,
            public_key_exponent BLOB NOT NULL,
            PRIMARY KEY(id)
        );

        CREATE TABLE IF NOT EXISTS tbl_api (
            id TEXT PRIMARY KEY,
            uri TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            signing_algorithm TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tbl_user (
            id TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            PRIMARY KEY(id),
            UNIQUE(email)
        );

        INSERT INTO tbl_api (id, uri, name, signing_algorithm) VALUES (?,?,?,?);
        INSERT INTO tbl_jwks (id, public_key, private_key, public_key_modules, public_key_exponent) VALUES (?,?,?,?,?);
    `, []any{
			api.Id, api.Uri, api.Name, api.SigningAlgorithm,
			jwks.Id, jwks.PublicKey, jwks.PrivateKey, jwks.PublicKeyModules, jwks.PublicKeyExponent,
		}
}

func (migration *migrationCreateTables) Down() (string, []any) {
	return `
        DROP TABLE tbl_user;
        DROP TABLE tbl_api;
        DROP TABLE tbl_jwks;
        DROP TABLE tbl_access_token;
        DROP TABLE tbl_authorization_code;
        DROP TABLE tbl_redirection_uri;
        DROP TABLE tbl_client;
    `, []any{}
}
