cmake_minimum_required(VERSION 3.14)
project(event_registration)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.2.0
)
FetchContent_MakeAvailable(Crow)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

add_executable(event_app main.cpp)
target_link_libraries(event_app PRIVATE Crow::Crow ${SQLITE3_LIBRARIES} crypt)
target_include_directories(event_app PRIVATE ${SQLITE3_INCLUDE_DIRS})
