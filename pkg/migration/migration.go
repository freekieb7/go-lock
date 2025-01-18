package migration

type Statement struct {
	Query     string
	Arguments []any
}

type Migration interface {
	Identifier() string
	Up() []Statement
	Down() []Statement
}
