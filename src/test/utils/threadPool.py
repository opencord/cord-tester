# 
# Copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import threading
import Queue

class PoolThread(threading.Thread):

    def __init__(self, requests_queue, wait_timeout, daemon, **kwds):
        threading.Thread.__init__(self, **kwds)
        self.daemon = daemon
        self._queue = requests_queue
        self._wait_timeout = wait_timeout
        self._finished = threading.Event()
        self.start()

    def run(self):
        while True:
            if(self._finished.isSet()):
                break

            try:
                work = self._queue.get(block=True, timeout=self._wait_timeout)
            except Queue.Empty:
                continue
            else:
                try:
                    work.__call__()
                finally:
                    self._queue.task_done()



class ThreadPool:

    def __init__(self, pool_size, daemon=False, queue_size=0, wait_timeout=5):
        """Set up the thread pool and create pool_size threads
        """
        self._queue = Queue.Queue(queue_size)
        self._daemon = daemon
        self._threads = []
        self._pool_size = pool_size
        self._wait_timeout = wait_timeout
        self.createThreads()


    def addTask(self, callableObject):
        if (callable(callableObject)):
            self._queue.put(callableObject, block=True)

    def cleanUpThreads(self):
        self._queue.join()

        for t in self._threads:
            t._finished.set()


    def createThreads(self):
        for i in range(self._pool_size):
            self._threads.append(PoolThread(self._queue, self._wait_timeout, self._daemon))


class CallObject:
    def __init__(self, v = 0): 
        self.v = v
    def callCb(self): 
        print 'Inside callback for %d' %self.v

if __name__ == '__main__':
    import multiprocessing
    callList = []
    cpu_count = multiprocessing.cpu_count()
    for i in xrange(cpu_count * 2):
        callList.append(CallObject(i))
    tp = ThreadPool(cpu_count * 2, queue_size=1, wait_timeout=1)
    for i in range(40):
        callObject = callList[i% (cpu_count*2)]
        f = callObject.callCb
        tp.addTask(f)

    tp.cleanUpThreads()


