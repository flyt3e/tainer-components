cmake_minimum_required(VERSION 3.2)
project(tainer-auth VERSION 1.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
include_directories(${PROJECT_SOURCE_DIR})

find_library(LIB_CRYPTO crypto)

add_library(tainer-auth SHARED tainer-auth.c)
target_link_libraries(tainer-auth ${LIB_CRYPTO})
install(TARGETS tainer-auth DESTINATION lib)
install(FILES ${PROJECT_SOURCE_DIR}/tainer-auth.h DESTINATION include)

add_executable(passwd passwd.c)
target_link_libraries(passwd tainer-auth)
install(TARGETS passwd DESTINATION bin)

add_executable(pwlogin pwlogin.c)
target_link_libraries(pwlogin tainer-auth)
install(TARGETS pwlogin DESTINATION bin)

add_executable(testauth testauth.c)
target_link_libraries(testauth tainer-auth)
