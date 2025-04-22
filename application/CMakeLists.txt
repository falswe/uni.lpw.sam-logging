# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# set(BOARD  dwm3001cdk)

#list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-dw3xxx-dev/)
#list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-dwm3001cdk/)
#list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../sam-core/)
#list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../sam-dw3000/)
#list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../sam-dwm3001cdk/)

find_package(Zephyr 3.2.0 REQUIRED HINTS $ENV{ZEPHYR_BASE})

message("${CMAKE_CURRENT_SOURCE_DIR}")

project(multi-ranging)

# SAM and its implementations
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/sam)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/sam_dw3000)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/sam_dwm3001cdk)
#file(GLOB SAM_SOURCES "src/sam/*.c")
#file(GLOB SAM_DW3000_SOURCES "src/sam_dw3000/*.c")
#file(GLOB SAM_DWM3001CDK_SOURCES "src/sam_dwm3001cdk/*.c")

# Application
target_sources(app PRIVATE
 #  ${SAM_SOURCES}
 #  ${SAM_DW3000_SOURCES}
 #  ${SAM_DWM3001CDK_SOURCES}
   src/main.c
)

#add_custom_command(
#	TARGET app
#	POST_BUILD
#	COMMAND ${PROJECT_SOURCE_DIR}/convert_compile_commands.sh "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json" "${PROJECT_SOURCE_DIR}/compile_commands.json"
#)

