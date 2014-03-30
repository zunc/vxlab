__author__ = 'khoai'

class Queue:
    def __init__(self):
        self.queue = []
    def push(self, data):
        self.queue.append(data)
    def pop(self):
        return self.queue.pop(0)
    def isEmpty(self):
        return False if len(self.queue) > 0 else True