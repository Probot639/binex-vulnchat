# Draft Makefile for the new SAML/Kerberos IdP pieces.
#
# I don't know how quickstart.sh currently builds kdc.c/main.cpp (direct cc
# invocation? an existing Makefile not shown in the tree?) so this is
# written to stand alone. Merge the kdc.c/main.cpp compile rules in once
# I can see them.

CC      = cc
CXX     = c++
CFLAGS  = -std=c11 -Wall -Wextra -g \
          $(shell pkg-config --cflags libxml-2.0 xmlsec1)
CXXFLAGS= -std=c++17 -Wall -Wextra -g
LDLIBS  = -lgssapi_krb5 -lkrb5 -luuid \
          $(shell pkg-config --libs libxml-2.0 xmlsec1) \
          -lmicrohttpd -lssl -lcrypto

SRC_DIR = src
OBJ     = $(SRC_DIR)/sp_registry.o \
          $(SRC_DIR)/gssapi_auth.o \
          $(SRC_DIR)/saml_assertion.o \
          $(SRC_DIR)/idp_http_server.o

idp: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(SRC_DIR)/*.o idp

.PHONY: clean