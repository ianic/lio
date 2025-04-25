sudo perf stat \
  -e io_uring:io_uring_complete                         \
  -e io_uring:io_uring_cqe_overflow                     \
  -e io_uring:io_uring_cqring_wait                      \
  -e io_uring:io_uring_create                           \
  -e io_uring:io_uring_defer                            \
  -e io_uring:io_uring_fail_link                        \
  -e io_uring:io_uring_file_get                         \
  -e io_uring:io_uring_link                             \
  -e io_uring:io_uring_local_work_run                   \
  -e io_uring:io_uring_poll_arm                         \
  -e io_uring:io_uring_queue_async_work                 \
  -e io_uring:io_uring_register                         \
  -e io_uring:io_uring_req_failed                       \
  -e io_uring:io_uring_short_write                      \
  -e io_uring:io_uring_submit_req                       \
  -e io_uring:io_uring_task_add                         \
  -e io_uring:io_uring_task_work_run                    \
-- timeout 2 /home/ianic/.local/bin/zig test src/tcp.zig --test-filter connect


# ps -o thcount $pid
