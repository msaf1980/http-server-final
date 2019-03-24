cmake_minimum_required( VERSION 2.6 )

set( BIN http-server )
project( ${BIN} )

set( SOURCE_ROOT src )
set( SOURCE_C_PROCS ~/workspace/lib/c/c_procs )
set( SOURCE_CPP_PROCS ~/workspace/lib/c++/cpp_procs )

#Scan dir for standart source files (*.c, *.cpp, etc)
aux_source_directory( ${SOURCE_ROOT} SOURCES )

include_directories( ${SOURCE_C_PROCS} ${SOURCE_CPP_PROCS} )

#aux_source_directory( ${SOURCE_C_PROCS} SOURCES )

set( SRC_C_PROCS
    ${SOURCE_C_PROCS}/procspawn/procspawn.c
    ${SOURCE_C_PROCS}/procutil/procutil.c
    ${SOURCE_C_PROCS}/pthreadutil/thrdpool.c
    ${SOURCE_C_PROCS}/fileutils.c
    ${SOURCE_C_PROCS}/strutils.c
    ${SOURCE_C_PROCS}/netutil/netutils.c
    ${SOURCE_C_PROCS}/netutil/mimetypes.c
    ${SOURCE_C_PROCS}/netutil/httpsrvutils.c
)
set( SRC_CPP_PROCS
    ${SOURCE_CPP_PROCS}/netutil/httputils.cpp
)

# install path for make install
set( INSTALL_PATH /usr/local/bin/ )

set( LIBRARIES
	stdc++
	pthread
)

set( C_FLAGS_DEBUG "-O0 -g3 -DDEBUG -pipe -Wall" )
set( C_FLAGS_RELEASE "-O3 -funroll-loops -fomit-frame-pointer -pipe" )
set( CXX_FLAGS_DEBUG "-O0 -g3 -DDEBUG -pipe -Wall" )
set( CXX_FLAGS_RELEASE "-O3 -funroll-loops -fomit-frame-pointer -pipe" )
#set( EXE_LINKER_FLAGS "-pipe" )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS_DEBUG}")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${C_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${CXX_FLAGS_DEBUG}")

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${C_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${CXX_FLAGS_RELEASE}")

add_executable( ${BIN} ${SOURCES} ${SRC_C_PROCS} ${SRC_CPP_PROCS} )
target_link_libraries( ${BIN} ${LIBRARIES} )

# Run when 'make install'
#target_link_libraries( ${BIN} ${LIBRARIES} )


#set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)
set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)

#set enable testing
add_subdirectory(test)
enable_testing()
