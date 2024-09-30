# src/core/worker.py
from PySide6.QtCore import QObject, Signal, Slot

class BaseWorker(QObject):
    """
    A base worker class for running long-running tasks in a separate thread.
    """
    finished = Signal()               # Signal emitted when the task is finished
    error = Signal(str)                # Signal emitted when an error occurs
    progress = Signal(str)             # Signal to update progress messages
    result = Signal(object)            # Signal to send back the result of the task

    def __init__(self, task_function, *args, **kwargs):
        """
        Initializes the worker with a task function and its arguments.
        :param task_function: The function to run in the separate thread.
        :param args: Arguments to pass to the function.
        :param kwargs: Keyword arguments to pass to the function.
        """
        super().__init__()
        self.task_function = task_function
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        """
        Runs the task function in a separate thread and emits signals based on the task status.
        """
        try:
            # Execute the task function and emit the result
            result = self.task_function(*self.args, **self.kwargs)
            self.result.emit(result)
        except Exception as e:
            # Emit the error signal with the error message
            self.error.emit(str(e))
        finally:
            # Emit the finished signal when done
            self.finished.emit()
