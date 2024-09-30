# src/features/thread_manager.py

from PySide6.QtCore import QObject, Signal, Slot
from concurrent.futures import ThreadPoolExecutor, Future
import traceback
from logs.logger import SafeKeepLogger

class ThreadManager(QObject):
    # Define signals to communicate with the GUI
    scan_completed_signal = Signal(str, dict)  # Signal to pass (path, result)
    scan_failed_signal = Signal(str, str)  # Signal to pass (path, error_message)

    def __init__(self, max_workers=4):
        super().__init__()
        self.logger = SafeKeepLogger().get_logger()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.logger.info("ThreadManager initialized with max workers: %d" % max_workers)

    def submit_task(self, function, *args, **kwargs):
        """
        Submit a task to the thread pool.
        :param function: The function to be executed.
        :param args: Positional arguments for the function.
        :param kwargs: Keyword arguments for the function.
        """
        try:
            future = self.executor.submit(function, *args, **kwargs)
            future.add_done_callback(lambda fut: self.on_task_completed(fut, *args, **kwargs))
            self.logger.info("Task submitted successfully.")
        except Exception as e:
            self.logger.error(f"Failed to submit task: {e}")
            self.scan_failed_signal.emit("Unknown", f"Failed to submit task: {e}")
    
    def on_task_completed(self, future: Future, *args, **kwargs):
        """
        Callback when a task is completed.
        :param future: The future object representing the completed task.
        """
        try:
            # Check if the task completed successfully
            if future.cancelled():
                self.logger.warning("Task was cancelled.")
                return
            if future.done():
                error = future.exception()
                if error:
                    self.logger.error(f"Task failed with exception: {error}")
                    self.scan_failed_signal.emit(args[0], str(error))  # Emit failure signal with path and error message
                else:
                    # If no error, get the result and emit the completion signal
                    result = future.result()
                    self.logger.info(f"Task completed successfully for {args[0]}.")
                    self.scan_completed_signal.emit(args[0], result)  # Emit success signal with path and result
        except Exception as e:
            self.logger.error(f"Exception in on_task_completed: {e}, Traceback: {traceback.format_exc()}")
            self.scan_failed_signal.emit(args[0], f"Exception in on_task_completed: {e}")
