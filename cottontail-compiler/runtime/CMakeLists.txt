# This file is part of the Cottontail runtime.
#
# The Cottontail runtime is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# The Cottontail runtime is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with the Cottontail runtime. If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.16)
project(CottontailRuntime)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
-Wredundant-decls -Wcast-align \
-Wmissing-include-dirs -Wswitch-default \
-Wextra -w -Winvalid-pch -Wredundant-decls -Wformat=2 \
-Wmissing-format-attribute -Wformat-nonliteral")

### changed -Wall to -w above THX

set(Cottontail_RT_AVAILABLE_BACKENDS "simple" "qsym")
string(REPLACE ";" ", " Cottontail_RT_AVAILABLE_BACKENDS_FMT "\{${Cottontail_RT_AVAILABLE_BACKENDS}\}")

set(Cottontail_RT_BACKEND "qsym" CACHE STRING "Cottontail Runtime Backend to build.\
Backends available: ${Cottontail_RT_AVAILABLE_BACKENDS_FMT}.")
option(Z3_TRUST_SYSTEM_VERSION "Use the system-provided Z3 without a version check" OFF)
set(LLVM_VERSION "" CACHE STRING "LLVM version to use. The corresponding LLVM dev package must be installed.")

# Place the final products in the top-level output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(Cottontail_RT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(Cottontail_RT_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(Cottontail_RT_BACKEND_DIR "${Cottontail_RT_SRC_DIR}/backends/${Cottontail_RT_BACKEND}")

# There is list(TRANSFORM ... PREPEND ...), but it's not available before CMake 3.12.
set(SHARED_RUNTIME_SOURCES
  ${Cottontail_RT_SRC_DIR}/Config.cpp
  ${Cottontail_RT_SRC_DIR}/RuntimeCommon.cpp
  ${Cottontail_RT_SRC_DIR}/LibcWrappers.cpp
  ${Cottontail_RT_SRC_DIR}/Shadow.cpp
  ${Cottontail_RT_SRC_DIR}/GarbageCollection.cpp)

# Backends should produce two targets: CottontailRtStatic (static library) and CottontailRtShared (shared library).
add_subdirectory("${Cottontail_RT_BACKEND_DIR}")

message(STATUS "Using ${Cottontail_RT_BACKEND} backend.")

if (NOT TARGET CottontailRtStatic)
  message(FATAL_ERROR "The backend \"${Cottontail_RT_BACKEND}\" does not produce the target CottontailRtStatic.\
This is a bug and it should be reported. Please open PR to the Cottontail-rt repository.")
endif()

if (NOT TARGET CottontailRtShared)
  message(FATAL_ERROR "The backend \"${Cottontail_RT_BACKEND}\" does not produce the target CottontailRtShared.\
This is a bug and it should be reported. Please open PR to the Cottontail-rt repository.")
endif()

target_link_libraries(CottontailRtShared stdc++fs)

set_target_properties(CottontailRtStatic PROPERTIES OUTPUT_NAME "Cottontail-rt")
set_target_properties(CottontailRtShared PROPERTIES OUTPUT_NAME "Cottontail-rt")
