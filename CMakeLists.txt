cmake_minimum_required(VERSION 3.20)
project(slaptop VERSION 0.7.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Language settings
# ---------------------------------------------------------------------------
# Conservative C++20: the target host ships GCC 11.5, so std::format and most
# of <ranges> are unavailable.  Keep to the subset GCC 11 implements fully.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SLAPTOP_WITH_TUI "Build the notcurses user interface" OFF)
option(SLAPTOP_WITH_LDAP "Build the cn=monitor collector (needs OpenLDAP headers)" OFF)
option(SLAPTOP_BUILD_TESTS "Build unit tests" ON)
option(SLAPTOP_STATIC_NOTCURSES
       "Link libnotcurses-core statically so the binary needs no notcurses install" OFF)
option(SLAPTOP_STATIC_DEPS
       "Also link notcurses dependencies statically when .a archives exist" OFF)

# ---------------------------------------------------------------------------
# Core library: collectors + model, no UI, no external dependencies.
# ---------------------------------------------------------------------------
add_library(slaptop_core STATIC
    src/collector/proc.cpp
    src/collector/discovery.cpp
    src/collector/logfile.cpp
    src/collector/configdir.cpp
    src/collector/behavior.cpp
    src/collector/lmdb.cpp
    src/collector/sshnode.cpp
    src/collector/io.cpp
    src/collector/limits.cpp
    src/collector/indexcheck.cpp
    src/ldaprc.cpp
    src/topology.cpp
    src/embedded.cpp
    src/engine.cpp
    src/config.cpp
)
target_include_directories(slaptop_core PUBLIC include)

# Warning set applied to every internal target.
function(slaptop_enable_warnings target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    endif()
endfunction()

slaptop_enable_warnings(slaptop_core)

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(slaptop src/main.cpp src/diagnose.cpp)
target_link_libraries(slaptop PRIVATE slaptop_core)
slaptop_enable_warnings(slaptop)

# The version lives in one place: project() above.  main.cpp reads the macro,
# so --version and the package metadata cannot drift apart.
#
# The commit is stamped next to it: a bug report that says "0.7.0" without the
# revision is a report about a guess.  A release tarball has no .git, and says
# "unknown" rather than lying; CI passes -DSLAPTOP_GIT_COMMIT=<sha> instead.
set(SLAPTOP_GIT_COMMIT "" CACHE STRING "Commit the binary was built from (auto-detected)")
if(NOT SLAPTOP_GIT_COMMIT)
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE _slaptop_commit OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE _slaptop_dirty OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
        if(_slaptop_commit)
            set(SLAPTOP_GIT_COMMIT "${_slaptop_commit}")
            if(_slaptop_dirty)
                string(APPEND SLAPTOP_GIT_COMMIT "-dirty")
            endif()
        endif()
    endif()
endif()
if(NOT SLAPTOP_GIT_COMMIT)
    set(SLAPTOP_GIT_COMMIT "unknown")
endif()
message(STATUS "slaptop ${PROJECT_VERSION} (${SLAPTOP_GIT_COMMIT})")
target_compile_definitions(slaptop PRIVATE
    SLAPTOP_VERSION="${PROJECT_VERSION}"
    SLAPTOP_COMMIT="${SLAPTOP_GIT_COMMIT}")

if(SLAPTOP_WITH_TUI)
    find_package(PkgConfig REQUIRED)
    target_sources(slaptop PRIVATE src/ui/tui.cpp)
    target_compile_definitions(slaptop PRIVATE SLAPTOP_WITH_TUI)

    # libunistring provides the UAX#29 grapheme segmentation the UI needs to
    # truncate text without splitting a cluster (accents, emoji sequences).
    # No .pc file exists on either host, so look for the header and library.
    find_path(UNISTRING_INCLUDE_DIR unigbrk.h
              HINTS /usr/include /usr/local/include /home/linuxbrew/.linuxbrew/include)
    find_library(UNISTRING_LIBRARY NAMES unistring
                 HINTS /usr/lib64 /usr/lib /usr/local/lib /home/linuxbrew/.linuxbrew/lib)
    if(NOT UNISTRING_INCLUDE_DIR OR (NOT UNISTRING_LIBRARY AND NOT SLAPTOP_UNISTRING_A))
        message(FATAL_ERROR "libunistring (unigbrk.h) is required for grapheme-aware truncation")
    endif()
    target_include_directories(slaptop PRIVATE "${UNISTRING_INCLUDE_DIR}")

    # Grapheme-aware text handling lives in its own small library so it can be
    # unit-tested without a terminal.
    add_library(slaptop_text STATIC src/ui/text.cpp)
    target_link_libraries(slaptop_text PUBLIC slaptop_core)
    target_include_directories(slaptop_text PUBLIC "${UNISTRING_INCLUDE_DIR}")
    slaptop_enable_warnings(slaptop_text)
    # The text module itself calls uc_grapheme_breaks(); with a static build the
    # archive must be linked here too, not only on the executable.
    if(SLAPTOP_UNISTRING_A)
        target_link_libraries(slaptop_text PUBLIC "${SLAPTOP_UNISTRING_A}")
    else()
        target_link_libraries(slaptop_text PUBLIC "${UNISTRING_LIBRARY}")
    endif()
    target_link_libraries(slaptop PRIVATE slaptop_text)

    if(NOT SLAPTOP_STATIC_NOTCURSES)
        pkg_check_modules(NOTCURSES REQUIRED IMPORTED_TARGET notcurses)
        target_link_libraries(slaptop PRIVATE PkgConfig::NOTCURSES)
    else()
        # The dashboard only uses core notcurses (planes, runes, input): no
        # multimedia codec is involved.  Linking libnotcurses-core.a drops the
        # notcurses runtime dependency, ffmpeg included, which is what makes a
        # single-file build possible.
        #
        # A notcurses built in a scratch prefix has no .pc file: when the archive
        # is given explicitly, its headers sit next to it.  Asking pkg-config for
        # a package that was never installed is what kept the release build from
        # working on a clean machine.
        if(SLAPTOP_NOTCURSES_CORE_A)
            get_filename_component(_slaptop_nc_lib "${SLAPTOP_NOTCURSES_CORE_A}" DIRECTORY)
            get_filename_component(_slaptop_nc_root "${_slaptop_nc_lib}" DIRECTORY)
            target_include_directories(slaptop PRIVATE "${_slaptop_nc_root}/include")
        else()
            pkg_check_modules(NOTCURSES REQUIRED notcurses)
            target_include_directories(slaptop PRIVATE ${NOTCURSES_INCLUDE_DIRS})
        endif()

        # Explicit archives win over discovery: this is how a minimal notcurses
        # (no ffmpeg, no libdeflate, no gpm) or a locally built libunistring is
        # plugged in.
        set(SLAPTOP_NOTCURSES_CORE_A "" CACHE FILEPATH
            "Path to a libnotcurses-core.a to embed (empty: auto-detect)")
        set(SLAPTOP_UNISTRING_A "" CACHE FILEPATH
            "Path to a libunistring.a to embed (empty: auto-detect)")
        set(SLAPTOP_DEFLATE_A "" CACHE FILEPATH
            "Path to a libdeflate.a to embed (needed where libdeflate.so.0 is absent)")

        if(SLAPTOP_NOTCURSES_CORE_A)
            set(NOTCURSES_CORE_A "${SLAPTOP_NOTCURSES_CORE_A}")
        else()
            find_file(NOTCURSES_CORE_A
                NAMES libnotcurses-core.a
                HINTS ${NOTCURSES_LIBRARY_DIRS} ${NOTCURSES_STATIC_LIBRARY_DIRS}
                      /usr/lib64 /usr/lib /usr/local/lib /usr/local/lib64
                      /home/linuxbrew/.linuxbrew/lib
                      ${CMAKE_PREFIX_PATH}/lib)
        endif()
        if(NOT NOTCURSES_CORE_A)
            message(FATAL_ERROR
                "SLAPTOP_STATIC_NOTCURSES=ON but libnotcurses-core.a was not found. "
                "Install the static package (dnf: notcurses-static).")
        endif()
        message(STATUS "Static notcurses core: ${NOTCURSES_CORE_A}")

        # Dependencies of the core, linked dynamically unless an explicit
        # archive is supplied.  Each is present on a stock RHEL 9 / Debian 12 /
        # Ubuntu 24.04 host; libdeflate is not, hence SLAPTOP_DEFLATE_A.
        set(SLAPTOP_TUI_DEPS "")
        foreach(dep gpm tinfo ncursesw)
            find_library(SLAPTOP_DEP_${dep} NAMES ${dep}
                         HINTS ${NOTCURSES_LIBRARY_DIRS}
                               ${NOTCURSES_STATIC_LIBRARY_DIRS})
            if(SLAPTOP_DEP_${dep})
                list(APPEND SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_${dep}})
            endif()
        endforeach()

        if(SLAPTOP_DEFLATE_A)
            list(APPEND SLAPTOP_TUI_DEPS "${SLAPTOP_DEFLATE_A}")
        else()
            find_library(SLAPTOP_DEP_deflate NAMES deflate)
            if(SLAPTOP_DEP_deflate)
                list(APPEND SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_deflate})
            endif()
        endif()

        if(SLAPTOP_UNISTRING_A)
            list(APPEND SLAPTOP_TUI_DEPS "${SLAPTOP_UNISTRING_A}")
        else()
            find_library(SLAPTOP_DEP_unistring NAMES unistring)
            if(SLAPTOP_DEP_unistring)
                list(APPEND SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_unistring})
            endif()
        endif()

        find_library(SLAPTOP_DEP_z NAMES z)
        if(SLAPTOP_DEP_z)
            list(APPEND SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_z})
        endif()

        if(SLAPTOP_STATIC_DEPS)
            foreach(archive gpm tinfo ncursesw unistring deflate)
                find_file(SLAPTOP_DEP_A_${archive} NAMES lib${archive}.a
                          HINTS ${NOTCURSES_STATIC_LIBRARY_DIRS} /usr/lib64 /usr/lib
                                /home/linuxbrew/.linuxbrew/lib ${CMAKE_PREFIX_PATH}/lib)
                if(SLAPTOP_DEP_A_${archive})
                    list(REMOVE_ITEM SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_${archive}})
                    list(APPEND SLAPTOP_TUI_DEPS ${SLAPTOP_DEP_A_${archive}})
                endif()
            endforeach()

            # libstdc++.a only ships with libstdc++-static on Fedora and with
            # the GCC toolchain elsewhere; skip the flag when it is absent
            # instead of failing the link.
            execute_process(
                COMMAND ${CMAKE_CXX_COMPILER} -print-file-name=libstdc++.a
                OUTPUT_VARIABLE SLAPTOP_LIBSTDCXX_A
                OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(EXISTS "${SLAPTOP_LIBSTDCXX_A}")
                target_compile_options(slaptop PRIVATE -static-libstdc++ -static-libgcc)
                target_link_options(slaptop PRIVATE -static-libstdc++ -static-libgcc)
            else()
                message(STATUS
                    "libstdc++.a not available: keeping the C++ runtime dynamic")
            endif()
        endif()

        target_link_libraries(slaptop PRIVATE ${NOTCURSES_CORE_A} ${SLAPTOP_TUI_DEPS} m pthread dl)

        # Static archives drag in whole objects; section GC keeps only what is
        # reachable (libunistring.a alone is 6 MB of tables).
        target_compile_options(slaptop PRIVATE -ffunction-sections -fdata-sections)
        target_link_options(slaptop PRIVATE -Wl,--gc-sections)
    endif()
endif()

if(SLAPTOP_WITH_LDAP)
    # Three supported setups:
    #  * a distribution with pkg-config metadata (ldap.pc);
    #  * an out-of-tree OpenLDAP build: headers in its include/,
    #    runtime in its lib/ (only libldap.so.2 exists there, no .so symlink);
    #  * prebuilt static archives, for a binary that runs where no libldap
    #    with this soname exists (Debian/Ubuntu ship libldap-2.x.so.0).
    set(SLAPTOP_LDAP_ROOT "" CACHE PATH "Root of an OpenLDAP install (include/ + lib/)")
    set(SLAPTOP_LDAP_LIBDIR "" CACHE PATH "Directory holding libldap.so.2 when it differs from ROOT/lib")
    set(SLAPTOP_LDAP_STATIC_A "" CACHE FILEPATH "libldap.a to embed (implies static LDAP)")
    set(SLAPTOP_LBER_STATIC_A "" CACHE FILEPATH "liblber.a to embed")
    set(SLAPTOP_SSL_STATIC_A "" CACHE FILEPATH "libssl.a to embed (TLS support)")
    set(SLAPTOP_CRYPTO_STATIC_A "" CACHE FILEPATH "libcrypto.a to embed (TLS support)")

    add_library(slaptop_ldap STATIC src/collector/ldap.cpp)
    target_link_libraries(slaptop_ldap PUBLIC slaptop_core)
    slaptop_enable_warnings(slaptop_ldap)
    # The flag is PUBLIC so engine.cpp (in core) also sees the LDAP code path.
    target_compile_definitions(slaptop_core PUBLIC SLAPTOP_WITH_LDAP)

    if(SLAPTOP_LDAP_STATIC_A)
        find_path(LDAP_INCLUDE_DIR ldap.h HINTS "${SLAPTOP_LDAP_ROOT}/include" REQUIRED)
        target_include_directories(slaptop_ldap PUBLIC "${LDAP_INCLUDE_DIR}")
        target_link_libraries(slaptop_ldap PUBLIC "${SLAPTOP_LDAP_STATIC_A}")
        foreach(archive SLAPTOP_LBER_STATIC_A SLAPTOP_SSL_STATIC_A SLAPTOP_CRYPTO_STATIC_A)
            if(${archive})
                target_link_libraries(slaptop_ldap PUBLIC "${${archive}}")
            endif()
        endforeach()
        # libldap.a resolves names and threads on its own.
        target_link_libraries(slaptop_ldap PUBLIC resolv pthread dl)
        message(STATUS "Static OpenLDAP client: ${SLAPTOP_LDAP_STATIC_A}")
    elseif(SLAPTOP_LDAP_ROOT)
        find_path(LDAP_INCLUDE_DIR ldap.h HINTS "${SLAPTOP_LDAP_ROOT}/include" REQUIRED)
        find_library(LDAP_LIBRARY NAMES ldap libldap.so.2
                     HINTS "${SLAPTOP_LDAP_ROOT}/lib" "${SLAPTOP_LDAP_LIBDIR}" REQUIRED)
        find_library(LBER_LIBRARY NAMES lber liblber.so.2
                     HINTS "${SLAPTOP_LDAP_ROOT}/lib" "${SLAPTOP_LDAP_LIBDIR}")
        message(STATUS "Using OpenLDAP from ${SLAPTOP_LDAP_ROOT}")
        target_include_directories(slaptop_ldap PUBLIC "${LDAP_INCLUDE_DIR}")
        target_link_libraries(slaptop_ldap PUBLIC "${LDAP_LIBRARY}")
        if(LBER_LIBRARY)
            target_link_libraries(slaptop_ldap PUBLIC "${LBER_LIBRARY}")
        endif()
        set_target_properties(slaptop PROPERTIES
            BUILD_RPATH "${SLAPTOP_LDAP_ROOT}/lib"
            INSTALL_RPATH "${SLAPTOP_LDAP_ROOT}/lib")
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(LDAP REQUIRED IMPORTED_TARGET ldap)
        target_link_libraries(slaptop_ldap PUBLIC PkgConfig::LDAP)
    endif()

    target_link_libraries(slaptop PRIVATE slaptop_ldap)
endif()

install(TARGETS slaptop RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SLAPTOP_BUILD_TESTS)
    enable_testing()
    add_executable(slaptop_tests tests/test_core.cpp)
    target_link_libraries(slaptop_tests PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests)
    add_test(NAME core COMMAND slaptop_tests)

    if(SLAPTOP_WITH_TUI)
        add_executable(slaptop_tests_text tests/test_text.cpp)
        target_link_libraries(slaptop_tests_text PRIVATE slaptop_text)
        slaptop_enable_warnings(slaptop_tests_text)
        add_test(NAME text COMMAND slaptop_tests_text)
    endif()

    add_executable(slaptop_tests_topology tests/test_topology.cpp)
    target_link_libraries(slaptop_tests_topology PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_topology)
    add_test(NAME topology COMMAND slaptop_tests_topology)

    add_executable(slaptop_tests_configdir tests/test_configdir.cpp)
    target_link_libraries(slaptop_tests_configdir PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_configdir)
    add_test(NAME configdir COMMAND slaptop_tests_configdir)

    add_executable(slaptop_tests_config tests/test_config.cpp)
    target_link_libraries(slaptop_tests_config PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_config)
    add_test(NAME config COMMAND slaptop_tests_config)

    add_executable(slaptop_tests_index tests/test_index.cpp)
    target_link_libraries(slaptop_tests_index PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_index)
    add_test(NAME index COMMAND slaptop_tests_index)

    add_executable(slaptop_tests_limits tests/test_limits.cpp)
    target_link_libraries(slaptop_tests_limits PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_limits)
    add_test(NAME limits COMMAND slaptop_tests_limits)

    add_executable(slaptop_tests_log tests/test_log.cpp)
    target_link_libraries(slaptop_tests_log PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_log)
    add_test(NAME log COMMAND slaptop_tests_log)

    add_executable(slaptop_tests_sshnode tests/test_sshnode.cpp)
    target_link_libraries(slaptop_tests_sshnode PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_sshnode)
    add_test(NAME sshnode COMMAND slaptop_tests_sshnode)

    add_executable(slaptop_tests_lmdb tests/test_lmdb.cpp)
    target_link_libraries(slaptop_tests_lmdb PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_lmdb)
    add_test(NAME lmdb COMMAND slaptop_tests_lmdb)

    add_executable(slaptop_tests_behavior tests/test_behavior.cpp)
    target_link_libraries(slaptop_tests_behavior PRIVATE slaptop_core)
    slaptop_enable_warnings(slaptop_tests_behavior)
    add_test(NAME behavior COMMAND slaptop_tests_behavior)

    add_executable(slaptop_tests_engine tests/test_engine.cpp)
    target_link_libraries(slaptop_tests_engine PRIVATE slaptop_core)
    if(SLAPTOP_WITH_LDAP)
        # engine.cpp carries the LDAP code path, whose symbols live in
        # slaptop_ldap.
        target_link_libraries(slaptop_tests_engine PRIVATE slaptop_ldap)
    endif()
    slaptop_enable_warnings(slaptop_tests_engine)
    add_test(NAME engine COMMAND slaptop_tests_engine)
endif()
