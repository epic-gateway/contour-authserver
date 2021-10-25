module gitlab.com/acnodal/epic/contour-authserver

go 1.14

require (
	github.com/envoyproxy/go-control-plane v0.9.5
	github.com/go-logr/logr v0.1.0
	github.com/mattn/go-isatty v0.0.8
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.4.0
	github.com/tg123/go-htpasswd v1.0.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55
	google.golang.org/grpc v1.26.0
	k8s.io/api v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v0.18.4
	sigs.k8s.io/controller-runtime v0.6.0
)
