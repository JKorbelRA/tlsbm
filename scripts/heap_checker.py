import csv
from pathlib import Path
from matplotlib import pyplot as plt
import numpy as np
import argparse


class HeapStatisticsTest:
    def __init__(self, name):
        self.state = "parsing_context"
        self.total_alloc = 0
        self.total_free = 0
        self.used = 0
        self.peak = 0

        self.consumed_stack = 0
        self.remaining_after_handshake = 0

        self.context_alloc = 0
        self.context_free = 0
        self.context_used = 0

        self.security_context_active = False
        self.handshake_active = False
        self.message_active = False

        self.cur_alloc_blocks = {}
        self.name = name

        self.y_axis_array = []
        self.x_axis_array = []

    def process_malloc(self, a_point):

        size_bytes = int(a_point["size_bytes"], 0)

        if self.security_context_active:
            self.context_alloc += size_bytes
            self.context_used += size_bytes
        else:
            self.total_alloc += size_bytes
            self.used += size_bytes

        self.cur_alloc_blocks[f"{a_point['ptr']}"] = {
            "size_bytes": size_bytes,
            "type": "context" if self.security_context_active else "handshake"
        }

    def process_realloc(self, a_point):
        # Free first
        freed_size = self.cur_alloc_blocks[f"{a_point['orig_ptr']}"]["size_bytes"]
        was_context = self.cur_alloc_blocks[f"{a_point['orig_ptr']}"]["type"] == "context"

        del self.cur_alloc_blocks[f"{a_point['ptr']}"]

        if was_context:
            self.context_free += freed_size
            self.context_used -= freed_size
        else:
            self.total_free += freed_size
            self.used -= freed_size

        # Malloc next
        size_bytes = int(a_point["size_bytes"], 0)

        if was_context:
            self.context_alloc += size_bytes
            self.context_used += size_bytes
        else:
            self.total_alloc += size_bytes
            self.used += size_bytes

        self.cur_alloc_blocks[f"{a_point['ptr']}"] = {
            "size_bytes": size_bytes,
            "type": "context" if self.security_context_active else "handshake"
        }

    def process_free(self, a_point):

        freed_size = self.cur_alloc_blocks[f"{a_point['ptr']}"]["size_bytes"]
        was_context = self.cur_alloc_blocks[f"{a_point['ptr']}"]["type"] == "context"

        del self.cur_alloc_blocks[f"{a_point['ptr']}"]

        if was_context:
            self.context_free += freed_size
            self.context_used -= freed_size
        else:
            self.total_free += freed_size
            self.used -= freed_size

    def process_begin_context(self):
        self.security_context_active = True

    def process_end_context(self):
        self.security_context_active = False

    def process_begin_handshake(self):
        self.handshake_active = True

    def process_end_handshake(self):
        self.handshake_active = False

    def process_begin_message(self):
        self.remaining_after_handshake = self.used
        self.message_active = True

    def process_end_message(self):
        self.message_active = False

    def process_stackcheck(self, a_point):
        self.consumed_stack = a_point["size_bytes"]

    def on_processed_point(self, i):
        used = self.used - self.context_used
        if used > self.peak:
            self.peak = used

        self.x_axis_array.append(i)
        self.y_axis_array.append(self.used)

    def draw(self):
        # X axis parameter:
        xaxis = np.array(self.x_axis_array)

        # Y axis parameter:
        yaxis = np.array(self.y_axis_array)

        plt.plot(xaxis, yaxis)
        plt.show()

    def print_statistics(self):
        print(f"--- {self.name} ---")
        print(f"Handshake Peak: {self.peak}")
        print(f"Handshake total alloc: {self.total_alloc}")
        print(f"Handshake total free: {self.total_free}")
        print(f"Handshake Remaining: {self.used}")
        print(f"Handshake Stack consumption: {self.consumed_stack}")
        if self.total_alloc != self.total_free:
            print("The TLS library is leaking handshake!")
        print(f"Context total alloc: {self.context_alloc}")
        print(f"Context total free: {self.context_free}")
        print(f"Context Remaining: {self.context_used}")
        if self.context_alloc != self.context_free:
            print("The TLS library is leaking context!")
        print(f"Remaining allocated after handshake: {self.remaining_after_handshake}")


class HeapStatistics:

    def file_to_points(self, heap_file):
        with open(heap_file, "r") as heap_fd:
            reader = csv.reader(heap_fd)
            i = 0
            for a_row in reader:
                if i > 0:
                    b_or_e = a_row[0] in ["B", "E"]
                    alloc_point = {
                        "op": a_row[0],
                        "ptr": a_row[1] if not b_or_e else "0x0",
                        "orig_ptr": a_row[2] if not b_or_e else "0x0",
                        "size_bytes": a_row[3] if not b_or_e else "0",
                        "name": a_row[1] if b_or_e else None
                    }
                    self.alloc_points.append(alloc_point)
                i += 1
        self.point_cnt = i-1 if i > 0 else 0

    def __init__(self, heap_file: Path):
        self.point_cnt = 0
        self.tests = []
        self.cur_test = None
        self.alloc_points = []
        self.file_to_points(heap_file)

    def process_begin_marker(self, a_point):
        name = a_point["name"]
        if name.startswith("Test:"):
            hst = HeapStatisticsTest(name)
            self.tests.append(hst)
            self.cur_test = hst
        if name == "Context":
            self.cur_test.process_begin_context()
        if name == "Handshake":
            self.cur_test.process_begin_handshake()
        if name == "Message":
            self.cur_test.process_begin_message()

    def process_end_marker(self, a_point):
        name = a_point["name"]
        if name.startswith("Test:"):
            self.cur_test = None
        if name == "Context":
            self.cur_test.process_end_context()
        if name == "Handshake":
            self.cur_test.process_end_handshake()
        if name == "Message":
            self.cur_test.process_end_message()

    def parse_alloc_points(self):
        i = 0

        for a_point in self.alloc_points:
            op = a_point["op"]
            if op == "M":
                self.cur_test.process_malloc(a_point)
            elif op == "R":
                self.cur_test.process_realloc(a_point)
            elif op == "F":
                self.cur_test.process_free(a_point)
            elif op == "B":
                self.process_begin_marker(a_point)
            elif op == "E":
                self.process_end_marker(a_point)
            elif op == "S":
                self.cur_test.process_stackcheck(a_point)
            else:
                assert False, f"unknown op {op}"

            if self.cur_test is not None:
                self.cur_test.on_processed_point(i)
            i += 1

    def draw(self):
        for a_test in self.tests:
            a_test.draw()

    def print_statistics(self):
        for a_test in self.tests:
            a_test.print_statistics()


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
