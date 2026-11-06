# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT

APP := ../../flipper/vaultflipper
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -I$(APP)
SRC := vf_native.c $(APP)/vf_core.c $(APP)/vf_totp.c $(APP)/lib/monocypher/monocypher.c

vf_native: $(SRC) $(APP)/vf_core.h $(APP)/vf_totp.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f vf_native
