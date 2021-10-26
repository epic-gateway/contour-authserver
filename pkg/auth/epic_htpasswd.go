// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/tg123/go-htpasswd"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	done = ctrl.Result{Requeue: false}
)

// EpicHtpasswd watches Secrets for htpasswd files and uses them for HTTP Basic Authentication.
type EpicHtpasswd struct {
	Log       logr.Logger
	Realm     string
	Client    client.Client
	Passwords map[string]*htpasswd.File // key: namespace string, value: passwords for that ns
	Selector  labels.Selector

	Lock sync.Mutex
}

var _ Checker = &EpicHtpasswd{}

// NewEpicHtpasswd returns an EpicHtpasswd. If err is non-nil then the
// EpicHtpasswd is not usable.
func NewEpicHtpasswd(
	logger logr.Logger, client client.Client,
	selector labels.Selector, realm string,
) (*EpicHtpasswd, error) {
	return &EpicHtpasswd{
		Log:       logger,
		Client:    client,
		Selector:  selector,
		Realm:     realm,
		Passwords: map[string]*htpasswd.File{},
	}, nil
}

// Set set the htpasswd file to use.
func (h *EpicHtpasswd) Set(namespace string, passwd *htpasswd.File) {
	h.Lock.Lock()
	defer h.Lock.Unlock()

	h.Passwords[namespace] = passwd
}

// Match authenticates the credential against the htpasswd file.
func (h *EpicHtpasswd) Match(namespace string, user string, pass string) bool {
	var (
		passwd *htpasswd.File
		hasPW  bool
	)

	// Arguably, getting and setting the pointer is atomic, but
	// Go doesn't make any guarantees.
	h.Lock.Lock()
	passwd, hasPW = h.Passwords[namespace]
	h.Lock.Unlock()
	if !hasPW {
		return false
	}

	if passwd != nil {
		// htpasswd.File locks internally, so all Match
		// calls will be serialized.
		return passwd.Match(user, pass)
	}

	return false
}

// Check ...
func (h *EpicHtpasswd) Check(ctx context.Context, request *Request) (*Response, error) {
	user, pass, ok := request.Request.BasicAuth()

	// Figure out the NS from the request path
	namespace, err := h.fetchNamespace(request.Request.URL.Path)
	if err != nil {
		h.Log.Info("can't find namespace in request",
			"host", request.Request.Host,
			"path", request.Request.URL.Path,
			"id", request.ID,
		)

		ok = false
	}

	h.Log.Info("checking request",
		"host", request.Request.Host,
		"path", request.Request.URL.Path,
		"id", request.ID,
		"ns", namespace,
		"user", user,
	)

	// If there's an "Authorization" header and we can verify it,
	// succeed and inject some headers to tell the origin what we did.
	if ok && h.Match(namespace, user, pass) {
		// TODO(jpeach) inject context attributes into the headers.
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler":  {"htpasswd"},
				"Auth-Username": {user},
				"Auth-Realm":    {h.Realm},
			},
		}

		// Reflect the authorization check context into the response headers.
		for k, v := range request.Context {
			key := fmt.Sprintf("Auth-Context-%s", k)
			key = http.CanonicalHeaderKey(key) // XXX(jpeach) this will not transform invalid characters

			authorized.Header.Add(key, v)
		}

		return &Response{
			Allow:    true,
			Response: authorized,
		}, nil
	}

	// If there's no "Authorization" header, or the authentication
	// failed, send an authenticate request.
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"WWW-Authenticate": {fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, h.Realm)},
			},
		},
	}, nil
}

// Reconcile ...
func (h *EpicHtpasswd) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	secret := v1.Secret{}

	// Read the secret that caused the event
	if err := h.Client.Get(context.Background(), req.NamespacedName, &secret); err != nil {
		// ignore not-found errors, since they can't be fixed by an
		// immediate requeue (we'll need to wait for a new notification),
		// and we get them when an object is deleted.
		return done, client.IgnoreNotFound(err)
	}

	// Only look at basic auth secrets.
	if secret.Annotations[AnnotationAuthType] != "basic" {
		return done, nil
	}

	// Accept the secret if it is for our realm or for any realm.
	if realm := secret.Annotations[AnnotationAuthRealm]; realm != "" {
		if realm != h.Realm && realm != "*" {
			return done, nil
		}
	}

	// Check for the "auth" key, which is the format used by ingress-nginx.
	authData, ok := secret.Data["auth"]
	if !ok {
		h.Log.Info("skipping Secret without \"auth\" key",
			"name", secret.Name, "namespace", secret.Namespace)
		return done, nil
	}

	// Do a pre-parse so that we can accept or reject whole Secrets.
	if newPasswd, err := htpasswd.NewFromReader(
		bytes.NewBuffer(authData),
		htpasswd.DefaultSystems,
		htpasswd.BadLineHandler(func(err error) {
			h.Log.Error(err, "skipping malformed Secret", "name", secret.Name, "namespace", secret.Namespace)
		}),
	); err != nil {
		h.Log.Error(err, "skipping malformed Secret", "name", secret.Name, "namespace", secret.Namespace)
	} else {
		// This Secret seems OK, so accumulate its content.
		h.Set(secret.Namespace, newPasswd)
	}

	return done, nil
}

// RegisterWithManager ...
func (h *EpicHtpasswd) RegisterWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(h)
}

func (h *EpicHtpasswd) fetchNamespace(path string) (string, error) {
	//                           0 1   2    3        4
	// the path should look like  /api/epic/accounts/{namespace}/foo/bar/...
	parts := strings.Split(path, "/")
	if len(parts) < 5 {
		return "", fmt.Errorf("namespace not found in path %s", path)
	}

	return "epic-" + parts[4], nil
}
