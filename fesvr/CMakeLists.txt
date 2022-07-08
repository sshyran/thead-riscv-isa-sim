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

cmake_minimum_required(VERSION 3.0.0)
project(fesvr VERSION 1.1.0)

# set c++11
set (CMAKE_CXX_STANDARD 11)

aux_source_directory(${PROJECT_SOURCE_DIR} FESVR_SRCS)
list(REMOVE_ITEM FESVR_SRCS
    ${PROJECT_SOURCE_DIR}/dtm.cc
    ${PROJECT_SOURCE_DIR}/elf2hex.cc
    ${PROJECT_SOURCE_DIR}/htif.cc
    ${PROJECT_SOURCE_DIR}/htif_hexwriter.cc
    ${PROJECT_SOURCE_DIR}/htif_pthread.cc
    ${PROJECT_SOURCE_DIR}/syscall.cc
    ${PROJECT_SOURCE_DIR}/term.cc
    ${PROJECT_SOURCE_DIR}/tsi.cc
)
message("fesvr=${FESVR_SRCS}")

# pthread
find_package(Threads REQUIRED)

# target
add_library(${PROJECT_NAME} INTERFACE)
target_sources(${PROJECT_NAME} INTERFACE ${FESVR_SRCS})
target_link_libraries(${PROJECT_NAME} INTERFACE ${CMAKE_THREAD_LIBS_INIT})