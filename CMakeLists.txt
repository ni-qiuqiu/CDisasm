cmake_minimum_required(VERSION 3.10) 


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY 
    ${CMAKE_SOURCE_DIR}/outputs/
) 

project(Cdisasm VERSION 0.1.0) 

set(CMAKE_CXX_STANDARD 17) 
set(CMAKE_CXX_FLAGS "-fno-rtti -fno-exceptions -DNDEBUG -fvisibility=hidden -Wno-narrowing -fdeclspec -pthread -w -s -fexceptions -Wall -O3"
)


add_executable(test_disasm 
    arm64_disasm.c
    arm64_disasm_utils.c
    arm64_disasm_loadstore.c
    arm64_disasm_dataproc.c
    arm64_disasm_branch.c
    test_disasm.c
)
