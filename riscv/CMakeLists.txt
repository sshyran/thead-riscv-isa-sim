# Copyright 2019-2021 T-Head Semiconductor Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.8.0)
project(riscv VERSION 1.1.0)

# set c++11
set (CMAKE_CXX_STANDARD 11)

aux_source_directory(${PROJECT_SOURCE_DIR} RISCV_SRCS)

list(REMOVE_ITEM RISCV_SRCS
${PROJECT_SOURCE_DIR}/clint.cc
${PROJECT_SOURCE_DIR}/debug_module.cc
${PROJECT_SOURCE_DIR}/devices.cc
${PROJECT_SOURCE_DIR}/dts.cc
${PROJECT_SOURCE_DIR}/insn_template.cc
${PROJECT_SOURCE_DIR}/interactive.cc
${PROJECT_SOURCE_DIR}/jtag_dtm.cc
${PROJECT_SOURCE_DIR}/rom.cc
)
message("RISCV=${RISCV_SRCS}")
#--------------------------------------

add_library(${PROJECT_NAME} INTERFACE)
target_sources(${PROJECT_NAME} INTERFACE ${RISCV_SRCS})
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE force_mod)