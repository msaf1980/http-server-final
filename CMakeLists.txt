cmake_minimum_required( VERSION 2.6 )

set( BIN final )
project( ${BIN} )

set( SOURCE_ROOT src )
#Scan dir for standart source files (*.c, *.cpp, etc)
aux_source_directory( ${SOURCE_ROOT} SOURCES )

# files with small reused procedures
set( SOURCE_EXT external )
aux_source_directory( ${SOURCE_EXT} SOURCES )

include_directories( ${SOURCE_EXT} )

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

add_executable( ${BIN} ${SOURCES} )
target_link_libraries( ${BIN} ${LIBRARIES} )

# Run when 'make install'
target_link_libraries( ${BIN} ${LIBRARIES} )


#set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)
set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)

#set enable testing
add_subdirectory(tests)
enable_testing()

