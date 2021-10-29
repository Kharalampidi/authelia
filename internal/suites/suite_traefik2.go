package suites

import (
	"fmt"
	"time"
)

var traefik2SuiteName = "Traefik2"

var traefik2DockerEnvironment = NewDockerEnvironment([]string{
	"internal/suites/docker-compose.yml",
	"internal/suites/Traefik2/docker-compose.yml",
	"internal/suites/example/compose/authelia/docker-compose.backend.{}.yml",
	"internal/suites/example/compose/authelia/docker-compose.frontend.{}.yml",
	"internal/suites/example/compose/redis/docker-compose.yml",
	"internal/suites/example/compose/nginx/backend/docker-compose.yml",
	"internal/suites/example/compose/traefik2/docker-compose.yml",
	"internal/suites/example/compose/smtp/docker-compose.yml",
	"internal/suites/example/compose/httpbin/docker-compose.yml",
})

func init() {
	setup := func(suitePath string) error {
		if err := traefik2DockerEnvironment.Up(); err != nil {
			return err
		}

		return waitUntilAutheliaIsReady(traefik2DockerEnvironment, traefik2SuiteName)
	}

	displayAutheliaLogs := func() error {
		backendLogs, err := traefik2DockerEnvironment.Logs("authelia-backend", nil)
		if err != nil {
			return err
		}

		fmt.Println(backendLogs)

		frontendLogs, err := traefik2DockerEnvironment.Logs("authelia-frontend", nil)
		if err != nil {
			return err
		}

		fmt.Println(frontendLogs)

		return nil
	}

	teardown := func(suitePath string) error {
		err := traefik2DockerEnvironment.Down()
		return err
	}

	GlobalRegistry.Register(traefik2SuiteName, Suite{
		SetUp:           setup,
		SetUpTimeout:    5 * time.Minute,
		OnSetupTimeout:  displayAutheliaLogs,
		OnError:         displayAutheliaLogs,
		TestTimeout:     1 * time.Minute,
		TearDown:        teardown,
		TearDownTimeout: 2 * time.Minute,
	})
}
