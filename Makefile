# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT

APP_DIR := flipper/vaultflipper
PROTO_SHA := 1c84fa48919cbb71d1cc65236fc0ee36740e24c6
PROTO_DIR := tools/.proto-gen

.PHONY: test fap launch native protos clean

test:
	cd companion && uv run pytest -q

native:
	$(MAKE) -C tests/native

fap:
	cd $(APP_DIR) && uvx ufbt

launch:
	cd $(APP_DIR) && uvx ufbt launch

protos:
	mkdir -p $(PROTO_DIR)/src
	for f in flipper application gui storage system desktop property gpio; do \
		curl -fsSL -o $(PROTO_DIR)/src/$$f.proto https://raw.githubusercontent.com/flipperdevices/flipperzero-protobuf/$(PROTO_SHA)/$$f.proto; \
	done
	uvx --from grpcio-tools python -m grpc_tools.protoc -I$(PROTO_DIR)/src --python_out=$(PROTO_DIR) $(PROTO_DIR)/src/*.proto

clean:
	rm -rf $(APP_DIR)/dist tests/native/vf_native $(PROTO_DIR)
