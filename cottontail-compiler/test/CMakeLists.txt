# This file is part of Cottontail.
#
# Cottontail is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# Cottontail is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Cottontail. If not, see <https://www.gnu.org/licenses/>.

if (Cottontail_RT_BACKEND STREQUAL "qsym")
  set(SYM_TEST_FILECHECK_ARGS "--check-prefix=QSYM --check-prefix=ANY")
elseif (Cottontail_RT_BACKEND STREQUAL "simple")
  set(SYM_TEST_FILECHECK_ARGS "--check-prefix=SIMPLE --check-prefix=ANY")
else()
  message(FATAL_ERROR "Unknown backend to test: ${Cottontail_RT_BACKEND}")
endif()

if (${LLVM_VERSION_MAJOR} VERSION_GREATER_EQUAL 14)
  # FileCheck used to be fine with unused prefixes when more than one prefix was
  # defined. This changed in LLVM version 14, requiring the new option
  # "--allow-unused-prefixes" (added in LLVM 13) to restore the old behavior.
  set(SYM_TEST_FILECHECK_ARGS "${SYM_TEST_FILECHECK_ARGS} --allow-unused-prefixes")
endif()

configure_file("lit.site.cfg.in" "lit.site.cfg")

add_custom_target(check
  lit
  --verbose
  --path=${LLVM_TOOLS_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Testing the system..."
  USES_TERMINAL)

add_dependencies(check CottontailRuntime Cottontail)
if (TARGET CottontailRuntime32)
    add_dependencies(check CottontailRuntime32 Cottontail)
endif()
