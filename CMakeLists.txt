cmake_minimum_required(VERSION 3.10)

# set the project name
project(tcl-sha)

find_package(TCL)
find_package(TclStub)

include_directories(${TCL_INCLUDE_PATH})
add_library(sha SHARED sha.c tclsha.c sha.h)
target_link_libraries(sha ${TCL_STUB_LIBRARY})
set_target_properties(sha PROPERTIES PREFIX "")
