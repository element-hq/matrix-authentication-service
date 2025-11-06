# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
#
# Set to 1 to run OPA through Docker
DOCKER := 0
PODMAN := 0
# Keep in sync with Dockerfile and .github/actions/build-policies/action.yml
OPA_DOCKER_IMAGE := docker.io/openpolicyagent/opa:1.8.0-debug
# Keep in sync with .github/workflows/ci.yaml
REGAL_DOCKER_IMAGE := ghcr.io/open-policy-agent/regal:0.36.1

INPUTS := \
	common/common.rego \
	client_registration/client_registration.rego \
	register/register.rego \
	authorization_grant/authorization_grant.rego \
	email/email.rego

ifeq ($(DOCKER), 1)
	OPA := docker run -i -v $(shell pwd):/policies:ro -w /policies --rm $(OPA_DOCKER_IMAGE)
	OPA_RW := docker run -i -v $(shell pwd):/policies -w /policies --rm $(OPA_DOCKER_IMAGE)
	REGAL := docker run -i -v $(shell pwd):/policies:ro -w /policies --rm $(REGAL_DOCKER_IMAGE)
else ifeq ($(PODMAN), 1)
	# When running rootless, the volume directory may need to be given global write permissions on the host
	OPA := podman run -i -v $(shell pwd):/policies:ro,Z -w /policies --rm $(OPA_DOCKER_IMAGE)
	OPA_RW := podman run -i -v $(shell pwd):/policies:Z -w /policies --rm $(OPA_DOCKER_IMAGE)
	REGAL := podman run -i -v $(shell pwd):/policies:ro,Z -w /policies --rm $(REGAL_DOCKER_IMAGE)
else
	OPA := opa
	OPA_RW := opa
	REGAL := regal
endif

policy.wasm: $(INPUTS)
	$(OPA_RW) build -t wasm \
		-e "client_registration/violation" \
		-e "register/violation" \
		-e "authorization_grant/violation" \
		-e "email/violation" \
		$^
	tar xzf bundle.tar.gz /policy.wasm
	$(RM) bundle.tar.gz
	touch $@

.PHONY: fmt
fmt:
	$(OPA_RW) fmt -w .

.PHONY: test
test:
	$(OPA) test --schema ./schema/ --ignore schema -v ./

.PHONY: coverage
coverage:
	$(OPA) test --coverage --schema ./schema/ --ignore schema ./ | $(OPA) eval --format pretty \
		--stdin-input \
		--data util/coveralls.rego \
		data.coveralls.from_opa > coverage.json

.PHONY: lint
lint:
	$(OPA) fmt -d --fail .
	$(OPA) check --strict --schema schema/ --ignore schema .
	$(REGAL) lint .
