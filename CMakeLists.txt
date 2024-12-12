cmake_minimum_required(VERSION 3.22)

project(kritis3m_wolfpkcs11)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_language(C ASM)

# Necessary to allow FetchContent_Populate
if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
endif()


# Options

# Use an externally installed WolfSSL library. If disabled, WolfSSL will be built.
option(KRITIS3M_WOLFPKCS11_EXTERNAL_WOLFSSL "Use external WolfSSL library" OFF)


# Make sure all libraries are installed in the lib directory (not lib64)
set(CMAKE_INSTALL_LIBDIR "lib")


# Pull in WolfSSL as dependency (either as an external library or as a subproject)
if(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Search for system-wide installed libraries in both lib and lib64 paths
        set(FIND_LIBRARY_USE_LIB32_PATHS TRUE)
        set(FIND_LIBRARY_USE_LIB64_PATHS TRUE)

        # Search for system-wide installed WolfSSL
        find_package(wolfssl REQUIRED)

else(KRITIS3M_ASL_EXTERNAL_WOLFSSL)
        # Pull in kritis3m_wolfssl as a dependency
        FetchContent_Declare(kritis3m_wolfssl
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl.git
                GIT_TAG                 origin/main
                GIT_PROGRESS            TRUE
                USES_TERMINAL_DOWNLOAD  TRUE
        )

        # Configuration
        set(KRITIS3M_WOLFSSL_STANDALONE OFF)
        set(KRITIS3M_WOLFSSL_ENABLE_FALCON OFF)
        set(BUILD_SHARED_LIBS OFF)
        set(CMAKE_C_FLAGS "-fPIC ${CMAKE_C_FLAGS}")

        # Actually add the external repositories to our project
        FetchContent_MakeAvailable(kritis3m_wolfssl)

        set(BUILD_SHARED_LIBS ON)
endif(KRITIS3M_ASL_EXTERNAL_WOLFSSL)


# External repositories we need
FetchContent_Declare(wolfpkcs11
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/wolfPKCS11.git
        GIT_TAG                 origin/development
        GIT_PROGRESS            TRUE
        USES_TERMINAL_DOWNLOAD  TRUE
)
FetchContent_Declare(kritis3m_applications
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
        GIT_TAG                 origin/main
        GIT_PROGRESS            TRUE
)

# Actually add the external repositories to our project
FetchContent_MakeAvailable(wolfpkcs11)

set(ENABLE_TCP_ECHO_SERVER OFF)
set(ENABLE_TCP_CLIENT_STDIN_BRIDGE OFF)
set(ENABLE_TLS_PROXY OFF)
set(ENABLE_NETWORK_TESTER OFF)
set(ENABLE_MANAGEMENT OFF)
FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
        FetchContent_Populate(kritis3m_applications)
        add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()


# Link the static WolfSSL library to the shared wolfPKCS11 library
target_link_libraries(wolfpkcs11 PRIVATE wolfssl "-Wl,--exclude-libs,ALL")


# Add executable to provision a wolfPKCS11 token
add_executable(wolfpkcs11_provision
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfpkcs11_provision.c
)
if (NOT MSVC)
        target_compile_options(wolfpkcs11_provision PUBLIC
                -Wall
                -Wextra
                -Wpedantic
                -Werror
                -march=native
                -fomit-frame-pointer
                -fdata-sections
                -ffunction-sections
                # -Wa,--noexecstack
                # -Wl,--gc-sections
        )
endif()

# Add the wolfPKCS11 library as a dependency
add_dependencies(wolfpkcs11_provision wolfpkcs11)
target_link_libraries(wolfpkcs11_provision PRIVATE kritis3m_applications_common)
target_link_libraries(wolfpkcs11_provision PRIVATE wolfssl)

# Install the wolfPKCS11 provisioning tool
install(TARGETS wolfpkcs11_provision DESTINATION ${CMAKE_INSTALL_BINDIR})
