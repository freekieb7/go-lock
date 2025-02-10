package scope

const (
	OfflineAccess = "offline_access"

	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	OpenId  string = "openid"
	Profile string = "profile"
	Email   string = "email"
	// Phone   string = "phone"

	CreateUsers string = "create:users"
	ReadUsers   string = "read:users"
	UpdateUsers string = "update:users"
	DeleteUsers string = "delete:users"

	CreateClients string = "create:clients"
	ReadClients   string = "read:clients"
	UpdateClients string = "update:clients"
	DeleteClients string = "delete:clients"

	CreateResourceServers string = "create:resource_servers"
	ReadResourceServers   string = "read:resource_servers"
	UpdateResourceServers string = "update:resource_servers"
	DeleteResourceServers string = "delete:resource_servers"

	CreateRoles string = "create:roles"
	ReadRoles   string = "read:roles"
	UpdateRoles string = "update:roles"
	DeleteRoles string = "delete:roles"
)
