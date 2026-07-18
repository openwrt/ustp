cmake_minimum_required(VERSION 3.12)

PROJECT(ustp C)

option(BUILD_TESTING "Build ustp tests" OFF)
include(CTest)
option(USTP_BUILD_DAEMON "Build and install ustpd" ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -g3 -Wmissing-declarations -Wno-error=missing-declarations -I${CMAKE_SOURCE_DIR})

if(USTP_BUILD_DAEMON)
	ADD_EXECUTABLE(ustpd bridge_track.c brmon.c hmac_md5.c libnetlink.c mstp.c netif_utils.c packet.c worker.c worker_queue.c config.c main.c ubus.c)
	TARGET_LINK_LIBRARIES(ustpd ubox ubus Threads::Threads)
endif()

SET(CMAKE_INSTALL_PREFIX /)

if(USTP_BUILD_DAEMON)
	INSTALL(TARGETS ustpd
		RUNTIME DESTINATION sbin
	)
	INSTALL(FILES scripts/bridge-stp
		DESTINATION sbin
	)
endif()

if(BUILD_TESTING)
	add_subdirectory(tests)
endif()
