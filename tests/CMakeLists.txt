## Testing the project
cmake_minimum_required(VERSION 2.6)

#include files including headers in the src
include_directories( . ../src ../external )

#add test sources
file( GLOB TEST_SOURCES *.c *.cpp )

file( GLOB LIB_SOURCE_FILES ../external/httputils.cpp )
add_library( source_lib ${LIB_SOURCE_FILES} )

#set enable testing
enable_testing()
link_libraries( ${LIBRARIES} )
link_libraries( source_lib ) 

#adding tests foreach test source file
foreach(filename ${TEST_SOURCES})
	
	#get the file name of the source file
	if(WIN32) 
		string(REGEX REPLACE ".*\\" "" testname "${filename}" )
	else(WIN32)
			string(REGEX REPLACE ".*/" "" testname "${filename}" )
	endif(WIN32)

	#remove .c extension
	string(REGEX REPLACE ".[a-z]+$" "" testname "${testname}" )

	#create executable
	add_executable( ${testname} ${OBJECTS} ${filename} )
	#configure for testing
	add_test( ${testname} ${testname} )
endforeach(filename)

