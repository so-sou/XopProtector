cmake_minimum_required(VERSION 3.22.1)
project(demo_biz)

add_library(demo_biz SHARED demo_biz.cpp)
find_library(log-lib log)
target_link_libraries(demo_biz ${log-lib})
target_link_options(demo_biz PRIVATE "-Wl,-z,max-page-size=16384")
