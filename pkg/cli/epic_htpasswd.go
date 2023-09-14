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

package cli

import (
	"net"

	"gitlab.com/acnodal/epic/contour-authserver/pkg/auth"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
)

// NewEpicHtpasswdCommand ...
func NewEpicHtpasswdCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "epic [OPTIONS]",
		Short: "Run an EPIC-compatible htpasswd basic authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := ctrl.Log.WithName("auth.epic")
			s := runtime.NewScheme()

			scheme.AddToScheme(s) //nolint(errcheck)

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:             s,
				MetricsBindAddress: mustString(cmd.Flags().GetString("metrics-address")),
			})
			if err != nil {
				return ExitErrorf(EX_CONFIG, "failed to create controller manager: %s", err)
			}

			secretsSelector, err := labels.Parse(mustString(cmd.Flags().GetString("selector")))
			if err != nil {
				return ExitErrorf(EX_CONFIG, "failed to parse secrets selector: %s", err)
			}

			htpasswd, err := auth.NewEpicHtpasswd(
				log, mgr.GetClient(),
				secretsSelector, mustString(cmd.Flags().GetString("auth-realm")),
			)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "failed to instantiate authenticator: %s", err)
			}

			if err := htpasswd.RegisterWithManager(mgr); err != nil {
				return ExitErrorf(EX_FAIL, "htpasswd controller registration failed: %w", err)
			}

			listener, err := net.Listen("tcp", mustString(cmd.Flags().GetString("address")))
			if err != nil {
				return ExitError{EX_CONFIG, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(EX_CONFIG, "invalid TLS configuration: %s", err)
			}

			auth.RegisterServer(srv, htpasswd)

			errChan := make(chan error)
			stopChan := ctrl.SetupSignalHandler()

			go func() {
				log.Info("started authorization server",
					"address", mustString(cmd.Flags().GetString("address")),
					"realm", htpasswd.Realm)

				if err := auth.RunServer(listener, srv, stopChan); err != nil {
					errChan <- ExitErrorf(EX_FAIL, "authorization server failed: %w", err)
				}

				errChan <- nil
			}()

			go func() {
				log.Info("started controller")

				if err := mgr.Start(stopChan); err != nil {
					errChan <- ExitErrorf(EX_FAIL, "controller manager failed: %w", err)
				}

				errChan <- nil
			}()

			select {
			case err := <-errChan:
				return err
			case <-stopChan:
				return nil
			}
		},
	}

	// Controller flags.
	cmd.Flags().String("metrics-address", ":8080", "The address the metrics endpoint binds to.")
	cmd.Flags().String("selector", "", "Selector (label-query) to filter Secrets, supports '=', '==', and '!='.")

	// GRPC flags.
	cmd.Flags().String("address", ":9090", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	// Authorization flags.
	cmd.Flags().String("auth-realm", "default", "Basic authentication realm.")

	return &cmd
}