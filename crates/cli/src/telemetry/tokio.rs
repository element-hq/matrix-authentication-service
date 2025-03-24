// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use opentelemetry::KeyValue;
use tokio::runtime::RuntimeMetrics;

use super::METER;

/// Install metrics for the tokio runtime.
#[allow(clippy::too_many_lines)]
pub fn observe(metrics: RuntimeMetrics) {
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.workers")
            .with_description("The number of worker threads used by the runtime")
            .with_unit("{worker}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.num_workers().try_into().unwrap_or(u64::MAX), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.blocking_threads")
            .with_description("The number of additional threads spawned by the runtime")
            .with_unit("{thread}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics
                        .num_blocking_threads()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }

    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.global_queue_depth")
            .with_description(
                "The number of tasks currently scheduled in the runtime’s global queue",
            )
            .with_unit("{task}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics.global_queue_depth().try_into().unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.idle_blocking_threads")
            .with_description("The number of idle threads, which have spawned by the runtime for `spawn_blocking` calls")
            .with_unit("{thread}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics
                        .num_idle_blocking_threads()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.remote_schedules")
            .with_description("The number of tasks scheduled from outside the runtime")
            .with_unit("{task}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.remote_schedule_count(), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.budget_forced_yields")
            .with_description("The number of times that tasks have been forced to yield back to the scheduler after exhausting their task budgets")
            .with_unit("{yield}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.budget_forced_yield_count(), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.io_driver.fd_registrations")
            .with_description("The number of file descriptors that have been registered with the runtime's I/O driver")
            .with_unit("{fd}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.io_driver_fd_registered_count(), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.io_driver.fd_deregistrations")
            .with_description("The number of file descriptors that have been deregistered by the runtime's I/O driver")
            .with_unit("{fd}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.io_driver_fd_deregistered_count(), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.io_driver.fd_readies")
            .with_description("The number of ready events processed by the runtime's I/O driver")
            .with_unit("{event}")
            .with_callback(move |instrument| {
                instrument.observe(metrics.io_driver_ready_count(), &[]);
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.global_queue_depth")
            .with_description(
                "The number of tasks currently scheduled in the runtime's global queue",
            )
            .with_unit("{task}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics.global_queue_depth().try_into().unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.blocking_queue_depth")
            .with_description("The number of tasks currently scheduled in the blocking thread pool, spawned using `spawn_blocking`")
            .with_unit("{task}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics
                        .blocking_queue_depth()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.park_count")
            .with_description("The total number of times the given worker thread has parked")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(metrics.worker_park_count(i), &[worker_idx(i)]);
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.noops")
            .with_description("The number of times the given worker thread unparked but performed no work before parking again")
            .with_unit("{operation}")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(
                        metrics.worker_noop_count(i),
                        &[worker_idx(i)],
                    );
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.task_steals")
            .with_description(
                "The number of tasks the given worker thread stole from another worker thread",
            )
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(metrics.worker_steal_count(i), &[worker_idx(i)]);
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.steal_operations")
            .with_description(
                "The number of times the given worker thread stole tasks from another worker thread",
            )
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(metrics.worker_steal_operations(i), &[worker_idx(i)]);
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.polls")
            .with_description("The number of tasks the given worker thread has polled")
            .with_unit("{task}")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(metrics.worker_poll_count(i), &[worker_idx(i)]);
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.busy_duration")
            .with_description("The amount of time the given worker thread has been busy")
            .with_unit("ms")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(
                        metrics
                            .worker_total_busy_duration(i)
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        &[worker_idx(i)],
                    );
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.local_schedules")
            .with_description("The number of tasks scheduled from **within** the runtime on the given worker's local queue")
            .with_unit("{task}")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(
                        metrics.worker_local_schedule_count(i),
                        &[worker_idx(i)],
                    );
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_counter("tokio_runtime.worker.overflows")
            .with_description(
                "The number of times the given worker thread saturated its local queue",
            )
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(metrics.worker_overflow_count(i), &[worker_idx(i)]);
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.worker.local_queue_depth")
            .with_description(
                "The number of tasks currently scheduled in the given worker's local queue",
            )
            .with_unit("{task}")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(
                        metrics
                            .worker_local_queue_depth(i)
                            .try_into()
                            .unwrap_or(u64::MAX),
                        &[worker_idx(i)],
                    );
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        let metrics = metrics.clone();
        METER
            .u64_observable_gauge("tokio_runtime.worker.mean_poll_time")
            .with_description("The mean duration of task polls, in nanoseconds")
            .with_unit("ns")
            .with_callback(move |instrument| {
                let num = metrics.num_workers();
                for i in 0..num {
                    instrument.observe(
                        metrics
                            .worker_mean_poll_time(i)
                            .as_nanos()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        &[worker_idx(i)],
                    );
                }
            })
            .build();
    }

    #[cfg(tokio_unstable)]
    {
        if metrics.poll_time_histogram_enabled() {
            // This adapts the histogram Tokio gives us to a format used by
            // OpenTelemetry. We're cheating a bit here, as we're only mimicking
            // a histogram using a counter.

            // Prepare the key-value pairs for the histogram buckets
            let mut buckets: Vec<_> = (0..metrics.poll_time_histogram_num_buckets())
                .map(|i| {
                    let range = metrics.poll_time_histogram_bucket_range(i);
                    let value = range.end.as_nanos().try_into().unwrap_or(i64::MAX);
                    let kv = KeyValue::new("le", value);
                    (i, kv)
                })
                .collect();

            // Change the last bucket to +Inf
            buckets.last_mut().unwrap().1 = KeyValue::new("le", "+Inf");

            // Prepare the key-value pairs for each worker
            let workers: Vec<_> = (0..metrics.num_workers())
                .map(|i| (i, worker_idx(i)))
                .collect();

            let metrics = metrics.clone();
            METER
                .u64_observable_gauge("tokio_runtime.worker.poll_time_bucket")
                .with_description("An histogram of the poll time of tasks, in nanoseconds")
                // We don't set a unit here, as it would add it as a suffix to the metric name
                .with_callback(move |instrument| {
                    for (worker, worker_idx) in &workers {
                        // Histogram buckets in OTEL accumulate values, whereas
                        // Tokio gives us the count wihtin each bucket, so we
                        // have to sum them as we go through them
                        let mut sum = 0;
                        for (bucket, le) in &buckets {
                            let count = metrics.poll_time_histogram_bucket_count(*worker, *bucket);
                            sum += count;
                            instrument.observe(sum, &[worker_idx.clone(), le.clone()]);
                        }
                    }
                })
                .build();
        }
    }

    {
        METER
            .u64_observable_gauge("tokio_runtime.alive_tasks")
            .with_description("The number of alive tasks in the runtime")
            .with_unit("{task}")
            .with_callback(move |instrument| {
                instrument.observe(
                    metrics.num_alive_tasks().try_into().unwrap_or(u64::MAX),
                    &[],
                );
            })
            .build();
    }
}

/// Helper to construct a [`KeyValue`] with the worker index.
#[allow(dead_code)]
fn worker_idx(i: usize) -> KeyValue {
    KeyValue::new("worker_idx", i.try_into().unwrap_or(i64::MAX))
}
