# Copyright (c) 2017 The Straks Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

STRAKS_CONFIG_INCLUDES=-I$(builddir)/config
STRAKS_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

STRAKS_INCLUDES += -I$(srcdir)/secp256k1/include
STRAKS_INCLUDES += $(UNIVALUE_CFLAGS)

LIBSTRAKS_SERVER=libstraks_server.a
LIBSTRAKS_COMMON=libstraks_common.a
LIBSTRAKS_CONSENSUS=libstraks_consensus.a
LIBSTRAKS_CLI=libstraks_cli.a
LIBSTRAKS_UTIL=libstraks_util.a
LIBSTRAKS_CRYPTO=crypto/libstraks_crypto.a
LIBSTRAKSQT=qt/libstraksqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBSTRAKS_ZMQ=libstraks_zmq.a
endif
if BUILD_STRAKS_LIBS
LIBSTRAKSCONSENSUS=libstraksconsensus.la
endif
if ENABLE_WALLET
LIBSTRAKS_WALLET=libstraks_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBSTRAKS_CRYPTO) \
  $(LIBSTRAKS_UTIL) \
  $(LIBSTRAKS_COMMON) \
  $(LIBSTRAKS_CONSENSUS) \
  $(LIBSTRAKS_SERVER) \
  $(LIBSTRAKS_CLI) \
  $(LIBSTRAKS_WALLET) \
  $(LIBSTRAKS_ZMQ)

lib_LTLIBRARIES = $(LIBSTRAKSCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_STRAKSD
  bin_PROGRAMS += straksd
endif

if BUILD_STRAKS_UTILS
  bin_PROGRAMS += straks-cli straks-tx
endif

.PHONY: FORCE check-symbols check-security
# straks core #
STRAKS_CORE_H = \
  activemasternode.h \
  addrdb.h \
  addressindex.h \
  spentindex.h \
  timestampindex.h \
  addrman.h \
  base58.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keepass.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  masternode.h \
  masternode-pos.h \
  masternodeman.h \
  masternodeconfig.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  protocol.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  rpc/register.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  spork.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libstraks_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between straksd and straks-qt
libstraks_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libstraks_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_server_a_SOURCES = \
  activemasternode.cpp \
  addrman.cpp \
  addrdb.cpp \
  bloom.cpp \
  blockencodings.cpp \
  bitpool.cpp \
  chain.cpp \
  checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(STRAKS_CORE_H)

if ENABLE_ZMQ
libstraks_zmq_a_CPPFLAGS = $(STRAKS_INCLUDES) $(ZMQ_CFLAGS)
libstraks_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between straksd and straks-qt, but only linked
# when wallet enabled
libstraks_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
libstraks_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_wallet_a_SOURCES = \
  activemasternode.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(STRAKS_CORE_H)

# crypto primitives library
crypto_libstraks_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_CONFIG_INCLUDES)
crypto_libstraks_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libstraks_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/aes_helper.c \
  crypto/Lyra2RE/Sponge.h \
  crypto/Lyra2RE/Sponge.c \
  crypto/Lyra2RE/Lyra2.h \
  crypto/Lyra2RE/Lyra2.c \
  crypto/Lyra2RE/blake.c \
  crypto/Lyra2RE/blake.h \
  crypto/Lyra2RE/keccak.c \
  crypto/Lyra2RE/keccak.h \
  crypto/Lyra2RE/skein.c \
  crypto/Lyra2RE/skein.h \
  crypto/Lyra2RE/cubehash.c \
  crypto/Lyra2RE/cubehash.h \
  crypto/Lyra2RE/bmw.c \
  crypto/Lyra2RE/bmw.h

# consensus: shared between all executables that validate any consensus rules.
libstraks_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
libstraks_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/straksconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between straksd, and straks-qt and non-server tools
libstraks_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
libstraks_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_common_a_SOURCES = \
  activemasternode.cpp \
  masternode.cpp \
  masternode-pos.cpp \
  masternodeconfig.cpp \
  masternodeman.cpp \
  amount.cpp \
  base58.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  spork.cpp \
  warnings.cpp \
  $(STRAKS_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libstraks_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
libstraks_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(STRAKS_CORE_H)

if GLIBC_BACK_COMPAT
libstraks_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between straks-cli and straks-qt
libstraks_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
libstraks_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libstraks_cli_a_SOURCES = \
  rpc/client.cpp \
  $(STRAKS_CORE_H)

nodist_libstraks_util_a_SOURCES = $(srcdir)/obj/build.h
#

# straksd binary #
straksd_SOURCES = straksd.cpp
straksd_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
straksd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
straksd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
straksd_SOURCES += straksd-res.rc
endif

straksd_LDADD = \
  $(LIBSTRAKS_SERVER) \
  $(LIBSTRAKS_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBSTRAKS_UTIL) \
  $(LIBSTRAKS_WALLET) \
  $(LIBSTRAKS_ZMQ) \
  $(LIBSTRAKS_CONSENSUS) \
  $(LIBSTRAKS_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

straksd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# straks-cli binary #
straks_cli_SOURCES = straks-cli.cpp
straks_cli_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES) $(EVENT_CFLAGS)
straks_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
straks_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
straks_cli_SOURCES += straks-cli-res.rc
endif

straks_cli_LDADD = \
  $(LIBSTRAKS_CLI) \
  $(LIBUNIVALUE) \
  $(LIBSTRAKS_UTIL) \
  $(LIBSTRAKS_CRYPTO)

straks_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# straks-tx binary #
straks_tx_SOURCES = straks-tx.cpp
straks_tx_CPPFLAGS = $(AM_CPPFLAGS) $(STRAKS_INCLUDES)
straks_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
straks_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
straks_tx_SOURCES += straks-tx-res.rc
endif

straks_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBSTRAKS_COMMON) \
  $(LIBSTRAKS_UTIL) \
  $(LIBSTRAKS_CONSENSUS) \
  $(LIBSTRAKS_CRYPTO) \
  $(LIBSECP256K1)

straks_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# straksconsensus library #
if BUILD_STRAKS_LIBS
include_HEADERS = script/straksconsensus.h
libstraksconsensus_la_SOURCES = $(crypto_libstraks_crypto_a_SOURCES) $(libstraks_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libstraksconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libstraksconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libstraksconsensus_la_LIBADD = $(LIBSECP256K1)
libstraksconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_STRAKS_INTERNAL
libstraksconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = $(CTAES_DIST)

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
