import re
import hashlib
import threading
import time
import json

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QMessageBox, QProgressBar,
    QSlider, QFileDialog, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

import ida_kernwin
import ida_name
import ida_funcs
import ida_bytes

class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(list)

class MatchWorker(threading.Thread):
    def __init__(self, base_funcs, target_funcs, signals, threshold, prefix_len=8):
        super().__init__()
        self.base_funcs = base_funcs
        self.target_funcs = target_funcs
        self.signals = signals
        self._is_running = True
        self.threshold = threshold
        self.prefix_len = prefix_len

    def stop(self):
        self._is_running = False

    def similarity_score(self, hash1: str, hash2: str) -> float:
        if not hash1 or not hash2:
            return 0.0
        length = min(len(hash1), len(hash2))
        matches = sum(1 for i in range(length) if hash1[i] == hash2[i])
        return matches / length

    def build_buckets(self, funcs):
        buckets = {}
        for addr, data in funcs.items():
            h = data["hash"]
            key = h[:self.prefix_len] if h and len(h) >= self.prefix_len else ""
            buckets.setdefault(key, []).append((addr, data))
        return buckets

    def run(self):
        try:
            matches = []
            total = len(self.base_funcs)
            target_buckets = self.build_buckets(self.target_funcs)
            for i, (b_addr, b_data) in enumerate(self.base_funcs.items()):
                if not self._is_running:
                    self.signals.status.emit("Canceled by user")
                    break

                best_score = 0.0
                best_t_addr = None
                best_t_name = None

                prefix = b_data["hash"][:self.prefix_len] if b_data["hash"] and len(b_data["hash"]) >= self.prefix_len else ""
                candidates = target_buckets.get(prefix, [])

                for t_addr, t_data in candidates:
                    score = self.similarity_score(b_data["hash"], t_data["hash"])
                    if score > best_score:
                        best_score = score
                        best_t_addr = t_addr
                        best_t_name = t_data["name"]

                if best_score >= self.threshold:
                    matches.append((b_addr, b_data["name"], best_t_addr, best_t_name, best_score * 100))
                else:
                    matches.append((b_addr, b_data["name"], "-", "-", 0.0))

                if i % 10 == 0:
                    self.signals.progress.emit(i)
                    self.signals.status.emit(f"Processing function {i}/{total}")

                time.sleep(0.001)

            self.signals.progress.emit(total)
            self.signals.status.emit("Matching finished")
            self.signals.result.emit(matches)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()

class SCREForm(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.layout = QVBoxLayout()
        self.parent.setLayout(self.layout)

        self.label_base = QLabel("Base: Current IDA functions")
        self.label_target = QLabel("Target: No target JSON loaded")
        self.status_label = QLabel("Status: Idle")

        # Buttons
        self.btn_export_base_json = QPushButton("Export Base Functions to JSON")
        self.btn_load_target_json = QPushButton("Load Target JSON")
        self.btn_run_match = QPushButton("Run Matching")
        self.btn_apply_rename = QPushButton("Apply Rename in Base")
        self.btn_cancel = QPushButton("Cancel Matching")
        self.btn_copy_results = QPushButton("Copy Results to Clipboard")

        self.btn_cancel.setEnabled(False)
        self.btn_apply_rename.setEnabled(False)
        self.btn_copy_results.setEnabled(False)

        # Table for results
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Base Addr", "Base Name", "Target Addr", "Target Name", "Match (%)"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)

        self.progress = QProgressBar()
        self.progress.setVisible(False)

        self.threshold_slider = QSlider(Qt.Horizontal)
        self.threshold_slider.setMinimum(0)    # from 0%
        self.threshold_slider.setMaximum(100)  # to 100%
        self.threshold_slider.setValue(65)     # default 65%
        self.threshold_slider.setTickInterval(5)
        self.threshold_slider.setTickPosition(QSlider.TicksBelow)
        self.threshold_label = QLabel("Threshold: 0.65")

        self.threshold_slider.valueChanged.connect(self.update_threshold_label)

        # Layouts
        h_layout_controls_top = QHBoxLayout()
        h_layout_controls_top.addWidget(self.btn_export_base_json)
        h_layout_controls_top.addWidget(self.btn_load_target_json)
        h_layout_controls_top.addWidget(self.btn_run_match)
        h_layout_controls_top.addWidget(self.btn_cancel)
        h_layout_controls_top.addWidget(self.btn_apply_rename)
        h_layout_controls_top.addWidget(self.btn_copy_results)

        h_layout_threshold = QHBoxLayout()
        h_layout_threshold.addWidget(QLabel("Match Threshold (0.00-1.00):"))
        h_layout_threshold.addWidget(self.threshold_slider)
        h_layout_threshold.addWidget(self.threshold_label)

        self.layout.addLayout(h_layout_controls_top)
        self.layout.addLayout(h_layout_threshold)
        self.layout.addWidget(self.label_base)
        self.layout.addWidget(self.label_target)
        self.layout.addWidget(self.status_label)
        self.layout.addWidget(self.table)
        self.layout.addWidget(self.progress)

        # Connect buttons
        self.btn_export_base_json.clicked.connect(self.export_base_to_json)
        self.btn_load_target_json.clicked.connect(self.load_target_json)
        self.btn_run_match.clicked.connect(self.run_match)
        self.btn_cancel.clicked.connect(self.cancel_match)
        self.btn_apply_rename.clicked.connect(self.apply_rename)
        self.btn_copy_results.clicked.connect(self.copy_results_to_clipboard)

        self.base_funcs = None
        self.target_funcs = None
        self.matches = []

        self.worker = None
        self.signals = WorkerSignals()

        self.signals.progress.connect(self.update_progress)
        self.signals.status.connect(self.update_status)
        self.signals.finished.connect(self.match_finished)
        self.signals.error.connect(self.match_error)
        self.signals.result.connect(self.match_result)

        self.load_base_funcs()

    def update_threshold_label(self, val):
        self.threshold_label.setText(f"Threshold: {val / 100:.2f}")

    def clean_and_demangle_name(self, name: str) -> str:
        if not name or name == "-":
            return name
        name = name.strip("_")
        name = re.sub(r'__+', '::', name)
        name = re.sub(r'(_(int|void|float|char|double|long|short|unsigned|signed))+', '', name)
        if '(' not in name and '::' in name:
            name += "(void)"
        demangled = ida_name.demangle_name(name, ida_name.MNG_LONG_FORM)
        if demangled:
            return demangled
        fallback = re.sub(r'_(void|int|float|char|double|long|short|unsigned|signed)$', '', name)
        if '::' in fallback and '(' not in fallback:
            fallback += "(void)"
        return fallback

    def load_base_funcs(self):
        self.label_base.setText("Base: Loading current IDA functions...")
        self.base_funcs = self.get_functions_hashes()
        self.label_base.setText(f"Base: Loaded {len(self.base_funcs)} functions.")

    def get_functions_hashes(self):
        funcs = {}
        for i in range(ida_funcs.get_func_qty()):
            f = ida_funcs.getn_func(i)
            if not f:
                continue
            start = f.start_ea
            end = f.end_ea
            size = end - start
            if size <= 0:
                continue
            func_bytes = ida_bytes.get_bytes(start, size)
            if not func_bytes:
                continue
            h = hashlib.md5(func_bytes).hexdigest()
            name = ida_funcs.get_func_name(start)
            funcs[start] = {"name": name, "hash": h}
        return funcs

    def export_base_to_json(self):
        if not self.base_funcs:
            QMessageBox.warning(self.parent, "Warning", "No base functions loaded to export.")
            return
        # Inform user about scope of export
        QMessageBox.information(
            self.parent,
            "Export Info",
            "Exported JSON is mainly useful for v36 libs or others with debug symbols."
        )
        funcs_list = []
        for addr, data in self.base_funcs.items():
            funcs_list.append({
                "address": addr,
                "name": data["name"],
                "hash": data["hash"]
            })
        path, _ = QFileDialog.getSaveFileName(
            self.parent, "Save Base Functions JSON", "base_functions.json", "JSON files (*.json)"
        )
        if path:
            try:
                with open(path, "w") as f_out:
                    json.dump(funcs_list, f_out, indent=2)
                QMessageBox.information(self.parent, "Export Success", f"Exported {len(funcs_list)} functions to JSON.")
            except Exception as e:
                QMessageBox.critical(self.parent, "Export Error", f"Failed to export JSON:\n{e}")

    def load_target_json(self):
        path, _ = QFileDialog.getOpenFileName(
            self.parent, "Select Target JSON Functions File", "", "JSON files (*.json)"
        )
        if not path:
            QMessageBox.information(self.parent, "Info", "Target JSON loading canceled.")
            return

        try:
            with open(path, "r") as f:
                data = json.load(f)
            funcs = {}
            for entry in data:
                addr = entry.get("address")
                name = entry.get("name", "-")
                hash_ = entry.get("hash", "")
                if addr is not None:
                    funcs[addr] = {"name": name, "hash": hash_}
            self.target_funcs = funcs
            self.label_target.setText(f"Target: Loaded {len(funcs)} functions from JSON.")
            self.btn_apply_rename.setEnabled(False)
            self.clear_table()
            self.status_label.setText("Status: Target JSON loaded, ready to match.")
        except Exception as e:
            QMessageBox.critical(self.parent, "Error", f"Failed to load target JSON:\n{e}")

    def clear_table(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        self.matches = []
        self.btn_copy_results.setEnabled(False)

    def run_match(self):
        if self.worker and self.worker.is_alive():
            QMessageBox.warning(self.parent, "Warning", "Matching already running.")
            return

        if not self.base_funcs or not self.target_funcs:
            QMessageBox.warning(self.parent, "Warning", "Load base and target functions first.")
            return

        self.clear_table()
        self.progress.setVisible(True)
        self.progress.setMaximum(len(self.base_funcs))
        self.progress.setValue(0)
        self.status_label.setText("Status: Starting matching...")

        threshold = self.threshold_slider.value() / 100.0

        self.worker = MatchWorker(self.base_funcs, self.target_funcs, self.signals, threshold)
        self.worker.start()
        self.btn_run_match.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_apply_rename.setEnabled(False)
        self.btn_copy_results.setEnabled(False)

    def cancel_match(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Status: Canceling...")

    def update_progress(self, value):
        self.progress.setValue(value)

    def update_status(self, text):
        self.status_label.setText(f"Status: {text}")

    def match_finished(self):
        self.btn_run_match.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    def match_error(self, error_msg):
        QMessageBox.critical(self.parent, "Matching Error", error_msg)
        self.btn_run_match.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.status_label.setText("Status: error")

    def match_result(self, matches):
        self.matches = matches
        self.table.setRowCount(len(matches))
        for i, (b_addr, b_name, t_addr, t_name, score) in enumerate(matches):
            addr_base_str = hex(b_addr) if isinstance(b_addr, int) else str(b_addr)
            addr_target_str = hex(t_addr) if (isinstance(t_addr, int) and t_addr != "-") else str(t_addr)

            b_name_clean = self.clean_and_demangle_name(b_name)
            t_name_clean = self.clean_and_demangle_name(t_name)

            self.table.setItem(i, 0, QTableWidgetItem(addr_base_str))
            self.table.setItem(i, 1, QTableWidgetItem(b_name_clean))
            self.table.setItem(i, 2, QTableWidgetItem(addr_target_str))
            self.table.setItem(i, 3, QTableWidgetItem(t_name_clean))
            item_score = QTableWidgetItem(f"{score:.2f}")
            item_score.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 4, item_score)

        self.btn_apply_rename.setEnabled(True)
        self.btn_copy_results.setEnabled(True)
        self.status_label.setText(f"Status: Matching finished with {len(matches)} functions.")
        self.progress.setVisible(False)

    def apply_rename(self):
        if not self.base_funcs or not self.matches:
            QMessageBox.warning(self.parent, "Warning", "Nothing to rename.")
            return

        try:
            count_ida = 0
            threshold = self.threshold_slider.value() / 100.0

            for b_addr, b_name, t_addr, t_name, score in self.matches:
                if t_name != "-" and score >= threshold:
                    clean_name = self.clean_and_demangle_name(t_name)
                    try:
                        if ida_funcs.get_func(b_addr):
                            if ida_name.set_name(b_addr, clean_name, ida_name.SN_FORCE):
                                count_ida += 1
                    except Exception as e:
                        print(f"Error renaming function at {hex(b_addr)} in IDA: {e}")

            QMessageBox.information(
                self.parent,
                "Rename Results",
                f"Renamed {count_ida} functions in IDA."
            )
            self.btn_apply_rename.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self.parent, "Rename Error", f"Error applying renames:\n{e}")

    def copy_results_to_clipboard(self):
        if not self.matches:
            QMessageBox.warning(self.parent, "Warning", "No matching results to copy.")
            return

        lines = ["BaseAddr\tBaseName\tTargetAddr\tTargetName\tMatch(%)"]
        for b_addr, b_name, t_addr, t_name, score in self.matches:
            addr_base_str = hex(b_addr) if isinstance(b_addr, int) else str(b_addr)
            addr_target_str = hex(t_addr) if (isinstance(t_addr, int) and t_addr != "-") else str(t_addr)
            lines.append(f"{addr_base_str}\t{b_name}\t{addr_target_str}\t{t_name}\t{score:.2f}")

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(lines))

        QMessageBox.information(self.parent, "Copied", "Matching results copied to clipboard.")

    def OnClose(self, form):
        if self.worker and self.worker.is_alive():
            self.worker.stop()

def main():
    form = SCREForm()
    form.Show("SC:RE 3.0 - Renaming Helper")

if __name__ == "__main__":
    main()
