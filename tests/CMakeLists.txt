find_package(Threads REQUIRED)

add_executable(test_worker_queue
	test_worker_queue.c
	../worker_queue.c
)
target_compile_options(test_worker_queue PRIVATE -Wall -Werror)
add_test(NAME worker_queue COMMAND test_worker_queue)

add_executable(test_netif_utils
	test_netif_utils.c
	../netif_utils.c
)
target_compile_definitions(test_netif_utils PRIVATE
	SYSFS_CLASS_NET="/tmp/ustp-test-sysfs"
)
target_compile_options(test_netif_utils PRIVATE -Wall -Werror)
add_test(NAME netif_utils COMMAND test_netif_utils)

add_executable(test_bridge_helpers test_bridge_helpers.c)
target_compile_options(test_bridge_helpers PRIVATE
	-Wall -Werror -Wno-error=format-truncation
	-ffunction-sections -fdata-sections
)
target_link_options(test_bridge_helpers PRIVATE -Wl,--gc-sections)
add_test(NAME bridge_helpers COMMAND test_bridge_helpers)

add_executable(test_mstp_priority
	test_mstp_priority.c
	../mstp.c
)
target_compile_options(test_mstp_priority PRIVATE -Wall -Werror)
add_test(NAME mstp_priority COMMAND test_mstp_priority)

add_executable(test_worker_shutdown
	test_worker_shutdown.c
	../worker.c
	../worker_queue.c
)
target_compile_options(test_worker_shutdown PRIVATE
	-Wall -Werror -ffunction-sections -fdata-sections
)
target_link_options(test_worker_shutdown PRIVATE -Wl,--gc-sections)
target_link_libraries(test_worker_shutdown Threads::Threads)
add_test(NAME worker_shutdown COMMAND test_worker_shutdown)
