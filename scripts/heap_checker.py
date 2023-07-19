import csv
from pathlib import Path
from matplotlib import pyplot as plt
import numpy as np
import argparse


class HeapStatistics:

    def file_to_points(self, heap_file):
        with open(heap_file, "r") as heap_fd:
            reader = csv.reader(heap_fd)
            i = 0
            for a_row in reader:
                if i > 0:
                    alloc_point = {
                        "op": a_row[0],
                        "ptr": a_row[1],
                        "orig_ptr": a_row[2],
                        "size_bytes": a_row[3],
                    }
                    self.alloc_points.append(alloc_point)
                i += 1
        self.point_cnt = i-1 if i > 0 else 0

    def __init__(self, heap_file: Path):
        self.point_cnt = 0
        self.total_alloc = 0
        self.total_free = 0
        self.used = 0
        self.peak = 0
        self.alloc_points = []
        self.cur_alloc_blocks = {}
        self.file_to_points(heap_file)

        self.y_axis_array = []
        self.x_axis_array = []

    def process_malloc(self, a_point):
        size_bytes = int(a_point["size_bytes"], 0)
        self.total_alloc += size_bytes
        self.used += size_bytes
        self.cur_alloc_blocks[f"{a_point['ptr']}"] = size_bytes

    def process_realloc(self, a_point):
        # Free first
        freed_size = self.cur_alloc_blocks[f"{a_point['orig_ptr']}"]
        del self.cur_alloc_blocks[f"{a_point['ptr']}"]

        self.total_free += freed_size
        self.used -= freed_size

        # Malloc next
        size_bytes = int(a_point["size_bytes"], 0)
        self.total_alloc += size_bytes
        self.used += size_bytes
        self.cur_alloc_blocks[f"{a_point['ptr']}"] = size_bytes

    def process_free(self, a_point):

        freed_size = self.cur_alloc_blocks[f"{a_point['ptr']}"]
        del self.cur_alloc_blocks[f"{a_point['ptr']}"]

        self.total_free += freed_size
        self.used -= freed_size
        pass

    def parse_alloc_points(self):
        i = 0

        for a_point in self.alloc_points:
            op = a_point["op"]
            if op == "M":
                self.process_malloc(a_point)
            elif op == "R":
                self.process_realloc(a_point)
            elif op == "F":
                self.process_free(a_point)
            else:
                assert False, f"unknown op {op}"

            if self.used > self.peak:
                self.peak = self.used

            self.x_axis_array.append(i)
            self.y_axis_array.append(self.used)
            i += 1

    def draw(self):
        # X axis parameter:
        xaxis = np.array(self.x_axis_array)

        # Y axis parameter:
        yaxis = np.array(self.y_axis_array)

        plt.plot(xaxis, yaxis)
        plt.show()

    def print_statistics(self):
        print("--- STATISTICS ---")
        print(f"Peak: {self.peak}")
        print(f"Total alloc: {self.total_alloc}")
        print(f"Total free: {self.total_free}")
        print(f"Remaining: {self.used}")
        assert self.total_alloc == self.total_free, "The TLS library is leaking!"


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--heap_file', default="heap.csv",
                        help='Path to the heap CSV file.')
    args = parser.parse_args()

    # op,ptr,orig_ptr,size_bytes
    alloc_points = []

    heap_file = Path(args.heap_file)

    hs = HeapStatistics(heap_file)
    hs.parse_alloc_points()
    hs.print_statistics()
    hs.draw()
