# yapps
Yet Another Python Port Scanner

YAPPS is a stupid simple python 3.5+ port scanner. It's nothing special. It uses asyncio (and uvloop on Unix) and the `open_connection` API function to determine if a TCP port is open. The only mgic here is the efficient way in which the coroutines are processed. Instead of creating a slew of coroutines and acquiring a single semaphore to permit locking/limiting by number of workers, it uses a tight CPU-bound loop to continuously check if any of the futures are completed.
