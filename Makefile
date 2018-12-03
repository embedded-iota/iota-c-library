SRC_DIR = src
IOTA_SRC_DIR = $(SRC_DIR)/iota
KECCAK_SRC_DIR = $(SRC_DIR)/keccak

BUILD_DIR = build

IOTA_OBJ = addresses bundle conversion kerl signing transfers common
KECCAK_OBJ = sha3
SRC_OBJ = aux
OBJ = $(IOTA_OBJ) $(KECCAK_OBJ) $(SRC_OBJ)

CFLAGS = -I$(SRC_DIR) -I$(IOTA_SRC_DIR) -I$(KECCAK_SRC_DIR)

$(IOTA_OBJ):%:$(IOTA_SRC_DIR)/%.c
	$(CC) -c -o $(BUILD_DIR)/$@.o $< $(CFLAGS)

$(KECCAK_OBJ):%:$(KECCAK_SRC_DIR)/%.c
	$(CC) -c -o $(BUILD_DIR)/$@.o $< $(CFLAGS)

$(SRC_OBJ):%:$(SRC_DIR)/%.c
	$(CC) -c -o $(BUILD_DIR)/$@.o $< $(CFLAGS)

lib: $(OBJ)
	ar -rs -o $(BUILD_DIR)/libiota_wallet.a $(OBJ:%=$(BUILD_DIR)/%.o)