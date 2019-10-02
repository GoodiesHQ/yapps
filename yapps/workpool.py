"""
An implementation of an asynchronous worker pool that will accept an unbounded
number of coroutines and efficiently runs tasks one at a time.
"""

from typing import Iterable, Coroutine
import asyncio


class WorkPool:
    """
    Pool of concurrent asynchronous workers with the ability to submit
    coroutines and unbounded generators that produce coroutines. Allows
    for highly scalable memory and CPU efficient concurrent applications.
    """

    def __init__(self, workers: int = 10, complete_callback: callable = None):
        """
        Create a finite set of workers that will concurrently interact with an
        unbounded amount of tasks.
        :param workers: the number of concurrent workers to utilize at a given time
        :param complete_callback: callback to execute once there are no more workers in the pool
        """
        self._sem = asyncio.Semaphore(workers)
        self._ccb = complete_callback
        self._wrk = set()

    def _on_task_complete(self, fut: asyncio.Future):
        """
        On completion of a future, remove it from the worker pool and release the
        semaphore to allow the worker pool to be repopulated
        :param fut: future provided to the callback
        :return:
        """
        self._wrk.remove(fut)
        self._sem.release()
        if self._ccb and len(self._wrk) == 0 and not self._sem.locked():
            # There are no workers and nothing has acquired the semaphore
            self._ccb()

    async def run(self, coro: Coroutine, *callbacks):
        """
        Schedule a coroutine to be run by a worker
        :param coro: coroutine to execute
        :param callbacks: callbacks to be executed upon completion of the coro
        :return: 
        """
        # Acquire a semaphore or wait until a worker is available
        await self._sem.acquire()
        fut = asyncio.ensure_future(coro)
        # Add all desired callbacks to be performed when the future is complete
        for callback in (self._on_task_complete, *callbacks):
            assert callable(callback)
            fut.add_done_callback(callback)
        # Add the future to the work pool
        self._wrk.add(fut)

    async def run_many(self, coro_iter: Iterable, *callbacks):
        for coro in coro_iter:
            await self.run(coro, *callbacks)

    async def join(self):
        await asyncio.gather(*self._wrk)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.join()
