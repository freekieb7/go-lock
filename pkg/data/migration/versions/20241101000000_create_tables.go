package migration_version

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"log"
	"strings"

	"github.com/freekieb7/go-lock/pkg/data/migration"
	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/freekieb7/go-lock/pkg/random"
	"github.com/freekieb7/go-lock/pkg/settings"
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
	resourceServer := model.ResourceServer{
		Id:               random.NewString(32),
		Name:             m.Settings.Name,
		Uri:              m.Settings.Host,
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

	statements := []migration.Statement{
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_client (
	        id TEXT NOT NULL,
	        secret BLOB NOT NULL,
	        name TEXT NOT NULL,
	        is_confidential INTEGER NOT NULL DEFAULT FALSE,
			redirect_uris TEXT NOT NULL,
	        PRIMARY KEY(id)
	    	);`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_authorization_code (
	        client_id TEXT NOT NULL,
	        code TEXT NOT NULL,
	        audience TEXT NOT NULL,
			scope TEXT NOT NULL,
			code_challenge TEXT,
	        PRIMARY KEY(client_id, code),
	        FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_access_token (
	        client_id TEXT NOT NULL,
	        token TEXT NOT NULL,
	        expiration_date NOT NULL,
	        PRIMARY KEY(client_id, token),
	        FOREIGN KEY(client_id) REFERENCES tbl_client(id) ON UPDATE CASCADE ON DELETE CASCADE
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_jwks (
	        id TEXT NOT NULL,
	        public_key BLOB NOT NULL,
	        private_key BLOB NOT NULL,
	        public_key_modules BLOB NOT NULL,
	        public_key_exponent BLOB NOT NULL,
	        PRIMARY KEY(id)
	    );`, Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_resource_server (
	        id TEXT NOT NULL,
	        uri TEXT NOT NULL UNIQUE,
	        name TEXT NOT NULL,
	        signing_algorithm TEXT NOT NULL,
			scopes TEXT NOT NULL,
			PRIMARY KEY(id)
	    );`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_user (
	        id TEXT NOT NULL,
	        email TEXT NOT NULL,
	        password TEXT NOT NULL,
	        PRIMARY KEY(id),
	        UNIQUE(email)
	    );`,
			Arguments: []any{},
		},
		{
			Query: `CREATE TABLE IF NOT EXISTS tbl_session (
	        id TEXT NOT NULL,
	        data BLOB NOT NULL,
	        PRIMARY KEY(id)
	    );`,
			Arguments: []any{},
		},
		{
			Query:     `INSERT INTO tbl_resource_server (id, uri, name, signing_algorithm, scopes) VALUES (?,?,?,?,?);`,
			Arguments: []any{resourceServer.Id, resourceServer.Uri, resourceServer.Name, resourceServer.SigningAlgorithm, strings.Join(resourceServer.Scopes, " ")},
		},
		{
			Query:     `INSERT INTO tbl_jwks (id, public_key, private_key, public_key_modules, public_key_exponent) VALUES (?,?,?,?,?);`,
			Arguments: []any{jwks.Id, jwks.PublicKey, jwks.PrivateKey, jwks.PublicKeyModules, jwks.PublicKeyExponent},
		},
	}

	return statements
}

func (*migration20241101000000) Down() []migration.Statement {

	return []migration.Statement{
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
