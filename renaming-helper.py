# Made with ChatGPT help, PT-BR: Feito com ajuda do ChatGPT
import ida_kernwin
import ida_name
import ida_funcs
import ida_bytes
import idaapi
import threading
import hashlib
import time
import json
import re
import binascii

from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QMessageBox, QProgressBar, QSlider, QApplication, QFileDialog, QTextEdit, QWidget, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

NULLSUB_PATTERN = re.compile(r"^(nullsub|voidsub|sub)_\d+$", re.IGNORECASE)

class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(list)
    log = pyqtSignal(str)

class MatchWorker(threading.Thread):
    def __init__(self, base_funcs, target_funcs, signals, threshold):
        super().__init__()
        self.base_funcs = base_funcs
        self.target_funcs = target_funcs
        self.signals = signals
        self.threshold = threshold
        self._is_running = True

    def stop(self):
        self._is_running = False

    def similarity_score(self, b1: bytes, b2: bytes) -> float:
        if not b1 or not b2:
            return 0.0
        length = min(len(b1), len(b2))
        if length == 0:
            return 0.0
        matches = 0
        for i in range(length):
            if b1[i] == b2[i]:
                matches += 1
        return matches / length

    def build_buckets(self, funcs):
        buckets = {}
        for addr, data in funcs.items():
            size = len(data["bytes"]) if "bytes" in data else 0
            key = size // 10  # bucket por faixa de tamanho de 10 bytes
            buckets.setdefault(key, []).append((addr, data))
        return buckets

    def run(self):
        try:
            matches = []
            total = len(self.base_funcs)
            target_buckets = self.build_buckets(self.target_funcs)

            for i, (b_addr, b_data) in enumerate(self.base_funcs.items()):
                if not self._is_running:
                    self.signals.status.emit("Cancelled by user")
                    self.signals.log.emit("Matching cancelled by user.")
                    break

                best_score = 0.0
                best_t_addr = None
                best_t_name = None

                b_size = len(b_data["bytes"])
                bucket_key = b_size // 10
                candidates = []
                for k in (bucket_key - 1, bucket_key, bucket_key + 1):
                    candidates.extend(target_buckets.get(k, []))

                for t_addr, t_data in candidates:
                    score = self.similarity_score(b_data["bytes"], t_data["bytes"])
                    if score > best_score:
                        best_score = score
                        best_t_addr = t_addr
                        best_t_name = t_data["name"]

                if best_score >= self.threshold:
                    matches.append((b_addr, b_data["name"], best_t_addr, best_t_name, best_score * 100))
                    self.signals.log.emit(f"Match found: Base {b_data['name']} @0x{b_addr:x} -> Target {best_t_name} @0x{best_t_addr:x} ({best_score*100:.2f}%)")
                else:
                    matches.append((b_addr, b_data["name"], None, None, 0.0))
                    self.signals.log.emit(f"No good match for base function {b_data['name']} @0x{b_addr:x}")

                if i % 10 == 0:
                    self.signals.progress.emit(i)
                    self.signals.status.emit(f"Matching {i}/{total} functions...")

                time.sleep(0.001)

            self.signals.progress.emit(total)
            self.signals.status.emit("Matching finished")
            self.signals.log.emit("Matching process finished.")
            self.signals.result.emit(matches)

        except Exception as e:
            self.signals.error.emit(str(e))
            self.signals.log.emit(f"Error during matching: {e}")
        finally:
            self.signals.finished.emit()

class RenamingPlugin(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._setup_ui()
        self._connect_signals()

        self.base_funcs = {}
        self.target_funcs = {}
        self.matches = []
        self.worker = None

        self.signals = WorkerSignals()

        self.signals.progress.connect(self._on_progress)
        self.signals.status.connect(self._on_status)
        self.signals.finished.connect(self._on_finished)
        self.signals.error.connect(self._on_error)
        self.signals.result.connect(self._on_result)
        self.signals.log.connect(self._on_log)

        self.load_base_functions()

    def _setup_ui(self):
        layout = QVBoxLayout()
        self.parent.setLayout(layout)

        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)

        top_widget = QWidget()
        top_layout = QVBoxLayout()
        top_widget.setLayout(top_layout)

        self.label_base = QLabel("Base: Not loaded")
        self.label_target = QLabel("Target: Not loaded")
        self.status_label = QLabel("Status: Idle")

        self.btn_load_json = QPushButton("Load Target JSON")
        self.btn_run_match = QPushButton("Run Matching")
        self.btn_apply_rename = QPushButton("Apply Renaming")
        self.btn_cancel = QPushButton("Cancel Matching")
        self.btn_copy_results = QPushButton("Copy Match Results")

        self.btn_apply_rename.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.btn_copy_results.setEnabled(False)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(self.btn_load_json)
        controls_layout.addWidget(self.btn_run_match)
        controls_layout.addWidget(self.btn_cancel)
        controls_layout.addWidget(self.btn_apply_rename)
        controls_layout.addWidget(self.btn_copy_results)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Base Addr", "Base Name", "Target Addr", "Target Name", "Match (%)"])
        self.table.horizontalHeader().setStretchLastSection(True)

        self.progress = QProgressBar()
        self.progress.setVisible(False)

        self.threshold_slider = QSlider(Qt.Horizontal)
        self.threshold_slider.setMinimum(0)
        self.threshold_slider.setMaximum(100)
        self.threshold_slider.setValue(65)
        self.threshold_slider.setTickInterval(5)
        self.threshold_slider.setTickPosition(QSlider.TicksBelow)
        self.threshold_label = QLabel("Threshold: 0.65")

        threshold_layout = QHBoxLayout()
        threshold_layout.addWidget(QLabel("Match Threshold:"))
        threshold_layout.addWidget(self.threshold_slider)
        threshold_layout.addWidget(self.threshold_label)

        top_layout.addLayout(controls_layout)
        top_layout.addLayout(threshold_layout)
        top_layout.addWidget(self.label_base)
        top_layout.addWidget(self.label_target)
        top_layout.addWidget(self.status_label)
        top_layout.addWidget(self.table)
        top_layout.addWidget(self.progress)

        splitter.addWidget(top_widget)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        splitter.addWidget(self.log_text)
        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)

    def _connect_signals(self):
        self.btn_load_json.clicked.connect(self.load_target_json)
        self.btn_run_match.clicked.connect(self.run_matching)
        self.btn_cancel.clicked.connect(self.cancel_matching)
        self.btn_apply_rename.clicked.connect(self.apply_renaming)
        self.btn_copy_results.clicked.connect(self.copy_results_to_clipboard)
        self.threshold_slider.valueChanged.connect(self._update_threshold_label)

    def _update_threshold_label(self, val):
        self.threshold_label.setText(f"Threshold: {val / 100:.2f}")

    def load_base_functions(self):
        self.status_label.setText("Loading base functions from IDA database...")
        self.log("Loading base functions from IDA database...")
        funcs = {}
        for i in range(ida_funcs.get_func_qty()):
            f = ida_funcs.getn_func(i)
            if not f:
                continue
            start = f.start_ea
            size = f.end_ea - start
            if size <= 0:
                continue
            bytes_ = ida_bytes.get_bytes(start, size)
            if not bytes_:
                continue
            name = ida_funcs.get_func_name(start)
            funcs[start] = {"name": name, "bytes": bytes_}
        self.base_funcs = funcs
        self.label_base.setText(f"Base: Loaded {len(funcs)} functions from IDA")
        self.status_label.setText("Base loaded")
        self.log(f"Loaded {len(funcs)} base functions.")

    def load_target_json(self):
        path, _ = QFileDialog.getOpenFileName(self.parent, "Open Target JSON", "", "JSON Files (*.json)")
        if not path:
            self.status_label.setText("Target JSON loading cancelled")
            self.log("Target JSON loading cancelled by user.")
            return

        try:
            with open(path, "r") as f:
                data = json.load(f)
            funcs = {}
            for addr_str, val in data.items():
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                if "bytes" not in val:
                    self.log(f"Target function at {addr_str} missing 'bytes', skipping")
                    continue
                bytes_raw = binascii.unhexlify(val["bytes"])
                funcs[addr] = {"name": val.get("name", ""), "bytes": bytes_raw}
            self.target_funcs = funcs
            self.label_target.setText(f"Target: Loaded {len(funcs)} functions from JSON")
            self.status_label.setText("Target loaded")
            self.log(f"Loaded {len(funcs)} target functions from JSON: {path}")
        except Exception as e:
            QMessageBox.warning(self.parent, "Error", f"Failed to load JSON: {e}")
            self.status_label.setText("Error loading target JSON")
            self.log(f"Error loading target JSON: {e}")

    def run_matching(self):
        if self.worker and self.worker.is_alive():
            QMessageBox.warning(self.parent, "Warning", "Matching already running")
            return

        if not self.base_funcs:
            QMessageBox.warning(self.parent, "Warning", "Base functions not loaded")
            self.log("Attempted to run matching but base functions not loaded.")
            return

        if not self.target_funcs:
            QMessageBox.warning(self.parent, "Warning", "Load target JSON first")
            self.log("Attempted to run matching but target JSON not loaded.")
            return

        self.matches = []
        self.table.setRowCount(0)
        self.progress.setVisible(True)
        self.progress.setMaximum(len(self.base_funcs))
        self.progress.setValue(0)
        self.status_label.setText("Starting matching...")
        self.log("Starting matching process...")

        threshold = self.threshold_slider.value() / 100.0

        self.worker = MatchWorker(self.base_funcs, self.target_funcs, self.signals, threshold)
        self.worker.start()
        self.btn_run_match.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_apply_rename.setEnabled(False)
        self.btn_copy_results.setEnabled(False)

    def cancel_matching(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Cancelling matching...")
            self.log("Matching cancellation requested.")

    def _on_progress(self, val):
        self.progress.setValue(val)

    def _on_status(self, text):
        self.status_label.setText(text)
        self.log(text)

    def _on_finished(self):
        self.btn_run_match.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress.setVisible(False)
        self.status_label.setText("Matching finished")
        self.log("Matching finished.")

    def _on_error(self, msg):
        QMessageBox.warning(self.parent, "Error", msg)
        self.status_label.setText("Error occurred")
        self.btn_run_match.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_copy_results.setEnabled(False)
        self.log(f"Error: {msg}")

    def _on_result(self, matches):
        self.matches = matches
        self.table.setRowCount(len(matches))

        for i, (b_addr, b_name, t_addr, t_name, score) in enumerate(matches):
            b_addr_str = f"0x{b_addr:x}" if isinstance(b_addr, int) else ""
            t_addr_str = f"0x{t_addr:x}" if isinstance(t_addr, int) else ""

            self.table.setItem(i, 0, QTableWidgetItem(b_addr_str))
            self.table.setItem(i, 1, QTableWidgetItem(b_name))
            self.table.setItem(i, 2, QTableWidgetItem(t_addr_str))
            self.table.setItem(i, 3, QTableWidgetItem(t_name or ""))
            self.table.setItem(i, 4, QTableWidgetItem(f"{score:.2f}"))

        self.btn_apply_rename.setEnabled(True)
        self.btn_copy_results.setEnabled(True)
        self.status_label.setText(f"Matching finished with {len(matches)} candidates")
        self.log(f"Matching finished with {len(matches)} candidates.")

    def apply_renaming(self):
        if not self.matches:
            QMessageBox.information(self.parent, "Info", "No matches to apply")
            self.log("Apply renaming called but no matches available.")
            return

        threshold = self.threshold_slider.value() / 100.0
        renamed_count = 0

        for b_addr, b_name, t_addr, t_name, score in self.matches:
            self.log(f"Checking function 0x{b_addr:x}: score={score:.2f}, target name={t_name}")

            if score < threshold:
                self.log(f"Skipping 0x{b_addr:x} because score {score:.2f} < threshold {threshold:.2f}")
                continue

            if not t_name:
                self.log(f"Skipping 0x{b_addr:x} because target name is None or empty")
                continue

            if not isinstance(b_addr, int):
                self.log(f"Skipping entry with invalid base address: {b_addr}")
                continue

            if NULLSUB_PATTERN.match(t_name):
                self.log(f"Skipping 0x{b_addr:x} because target name '{t_name}' matches nullsub pattern")
                continue

            if b_addr not in self.base_funcs:
                self.log(f"Skipping 0x{b_addr:x} because base address not found in base functions")
                continue

            try:
                current_name = ida_name.get_name(b_addr)
                if current_name == t_name:
                    self.log(f"Name already correct for 0x{b_addr:x}: {current_name}")
                    continue

                ida_name.set_name(b_addr, t_name, ida_name.SN_FORCE)
                renamed_count += 1
                self.log(f"Renamed function 0x{b_addr:x} from '{current_name}' to '{t_name}'")
            except Exception as e:
                self.log(f"Error renaming function 0x{b_addr:x}: {e}")

        QMessageBox.information(self.parent, "Rename complete", f"Renamed {renamed_count} functions")
        self.log(f"Renaming complete. {renamed_count} functions renamed.")

    def copy_results_to_clipboard(self):
        if not self.matches:
            QMessageBox.information(self.parent, "Info", "No match results to copy")
            self.log("Copy results called but no matches available.")
            return

        lines = []
        header = "Base Addr\tBase Name\tTarget Addr\tTarget Name\tMatch (%)"
        lines.append(header)
        for b_addr, b_name, t_addr, t_name, score in self.matches:
            b_addr_str = f"0x{b_addr:x}" if isinstance(b_addr, int) else ""
            t_addr_str = f"0x{t_addr:x}" if isinstance(t_addr, int) else ""
            line = f"{b_addr_str}\t{b_name}\t{t_addr_str}\t{t_name or ''}\t{score:.2f}"
            lines.append(line)

        text = "\n".join(lines)
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self.parent, "Copied", "Match results copied to clipboard")
        self.log("Copied match results to clipboard.")

    def _on_log(self, msg):
        self.log_text.append(msg)
        self.log_text.moveCursor(self.log_text.textCursor().End)

    def log(self, msg):
        self._on_log(msg)

    def OnClose(self, form):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.log("Stopped running worker thread.")

def PLUGIN_ENTRY():
    return RenamingPlugin()

def main():
    plugin = RenamingPlugin()
    plugin.Show("SC:RE - Renaming Helper")

if __name__ == "__main__":
    main()
