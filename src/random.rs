//! Cryptographically strong pseudo-random number generation.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::sync::Arc;

use bytes::{BufMut, BytesMut, Bytes};
use futures::{Async, Future, Poll};
use futures::future::{Executor, ExecuteError};
use futures::sync::oneshot::{Execute, SpawnHandle, spawn};
use futures_cpupool::CpuPool;
use openssl;

use super::Error;

/// Cryptographically strong pseudo-random number generator.
#[derive(Clone, Debug)]
pub struct Generator {
    executor: TaskExecutor
}

impl Generator {
    /// Create a new generator backed by a thread pool.
    ///
    /// The `threads` argument indicates the number of threads to spawn.
    pub fn new(threads: usize) -> Self {
        Generator::with_executor(CpuPool::new(threads))
    }

    /// Create a new generator backed by an `Executor`.
    pub fn with_executor<E: Executor<Task> + 'static>(executor: E) -> Self {
        Generator {
            executor: TaskExecutor { inner: Arc::new(executor) }
        }
    }

    /// Generate cryptographically strong pseudo-random data.
    ///
    /// The `size` argument indicates the number of bytes to generate.
    pub fn random_bytes(&self, size: usize) -> RandomBytes {
        RandomBytes {
            size: size,
            executor: self.executor.clone(),
            state: State::Idle
        }
    }
}

#[derive(Debug)]
enum State {
    Idle,
    Busy(SpawnHandle<Bytes, Error>)
}

/// Future returning cryptographically strong pseudo-random data.
#[derive(Debug)]
pub struct RandomBytes {
    size: usize,
    executor: TaskExecutor,
    state: State 
}

impl Future for RandomBytes {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.state {
            State::Busy(ref mut future) => future.poll(),
            State::Idle => {
                let task_inner = TaskInner { size: self.size };
                let spawn_handle = spawn(task_inner, &self.executor);
                self.state = State::Busy(spawn_handle);
                self.poll()
            }
        }
    }
}

#[derive(Clone)]
struct TaskExecutor {
    inner: Arc<Executor<Task>>
}

impl Debug for TaskExecutor {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("TaskExecutor").finish()
    }
}

impl Executor<Execute<TaskInner>> for TaskExecutor {
    fn execute(&self, future: Execute<TaskInner>) -> Result<(), ExecuteError<Execute<TaskInner>>> {
        match self.inner.execute(Task { inner: future }) {
            Ok(()) => Ok(()),
            Err(err) =>
                Err(ExecuteError::new(err.kind(), err.into_future().inner))
        }
    }
}

/// Blocking task that should be executed on a thread pool.
pub struct Task {
    inner: Execute<TaskInner>
}

impl Debug for Task {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("Task").finish()
    }
}

impl Future for Task {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

struct TaskInner {
    size: usize
}

impl Future for TaskInner {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut output = BytesMut::with_capacity(self.size);
        unsafe {
            openssl::rand::rand_bytes(output.bytes_mut())
                .map_err(|err| Error(err).into())?;
            output.advance_mut(self.size);
        }
        Ok(Async::Ready(output.freeze()))
    }
}

#[cfg(test)]
mod test {
    use futures::Future;

    use super::Generator;

    #[test]
    fn random_bytes() {
        let generator = Generator::new(1);
        let random_bytes = generator.random_bytes(128).wait().unwrap();
        assert_eq!(random_bytes.len(), 128);
    }
}