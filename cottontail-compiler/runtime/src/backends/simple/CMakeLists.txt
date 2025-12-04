# This file is part of theCottontail runtime.
#
# TheCottontail runtime is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# TheCottontail runtime is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# withCottontail. If not, see <https://www.gnu.org/licenses/>.

find_package(Z3 4 CONFIG)
if (NOT Z3_FOUND)
  if (NOT Z3_TRUST_SYSTEM_VERSION)
    message(FATAL_ERROR "Couldn't locate Z3. \
If you want me to trust that a suitable version is available nonetheless, \
configure CMake with -DZ3_TRUST_SYSTEM_VERSION=on (see also docs/Configuration.txt).")
  else()
    if (EXISTS "/usr/include/z3")
      set(Z3_C_INCLUDE_DIRS "/usr/include/z3")
    else()
      set(Z3_C_INCLUDE_DIRS)
    endif()
    set(Z3_LIBRARIES "z3")
  endif()
endif()

set(CottontailRtSrc ${SHARED_RUNTIME_SOURCES} Runtime.cpp)

add_library(CottontailRtObj OBJECT
        ${CottontailRtSrc})

set_property(TARGET CottontailRtObj PROPERTY POSITION_INDEPENDENT_CODE 1)

add_library(CottontailRtShared SHARED $<TARGET_OBJECTS:CottontailRtObj>)
add_library(CottontailRtStatic STATIC $<TARGET_OBJECTS:CottontailRtObj>)

set(CottontailRtDeps ${Z3_LIBRARIES})

# Object libraries cannot be linked directly
# https://gitlab.kitware.com/cmake/cmake/-/issues/18090
target_link_libraries(CottontailRtShared ${CottontailRtDeps})
target_link_libraries(CottontailRtStatic ${CottontailRtDeps})

target_include_directories(CottontailRtObj PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${Cottontail_RT_INCLUDE_DIR}
  ${Z3_C_INCLUDE_DIRS})

set_target_properties(CottontailRtObj PROPERTIES COMPILE_FLAGS "-Werror -Wno-error=deprecated-declarations")
