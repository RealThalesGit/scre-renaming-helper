import sqlite3
import threading
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTableWidget,
    QTableWidgetItem, QMessageBox, QProgressBar
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from ida_kernwin import PluginForm
import ida_name
import ida_funcs


class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(list)


class MatchWorker(threading.Thread):
    def __init__(self, base_funcs, target_funcs, signals):
        super().__init__()
        self.base_funcs = base_funcs
        self.target_funcs = target_funcs
        self.signals = signals
        self._is_running = True

    def stop(self):
        self._is_running = False

    def similarity_score(self, hash1: str, hash2: str) -> float:
        if not hash1 or not hash2:
            return 0.0
        length = min(len(hash1), len(hash2))
        matches = sum(1 for i in range(length) if hash1[i] == hash2[i])
        return matches / length

    def run(self):
        try:
            threshold = 0.65
            matches = []
            total = len(self.base_funcs)
            for i, (b_addr, b_data) in enumerate(self.base_funcs.items()):
                if not self._is_running:
                    self.signals.status.emit("Canceled by user")
                    break

                best_score = 0.0
                best_t_addr = None
                best_t_name = None

                for t_addr, t_data in self.target_funcs.items():
                    score = self.similarity_score(b_data["hash"], t_data["hash"])
                    if score > best_score:
                        best_score = score
                        best_t_addr = t_addr
                        best_t_name = t_data["name"]

                if best_score >= threshold:
                    matches.append((
                        b_addr, b_data["name"], best_t_addr, best_t_name, best_score * 100
                    ))
                else:
                    matches.append((
                        b_addr, b_data["name"], "-", "-", 0.0
                    ))

                if i % 10 == 0:
                    self.signals.progress.emit(i)
                    self.signals.status.emit(f"Processing function {i}/{total}")

                time.sleep(0.001)  # yield CPU

            self.signals.progress.emit(total)
            self.signals.status.emit("Matching finished")
            self.signals.result.emit(matches)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            self.signals.finished.emit()


class DiaphoraForm(PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        self.layout = QVBoxLayout()
        self.parent.setLayout(self.layout)

        self.label_base = QLabel("Base DB: None")
        self.label_target = QLabel("Target DB: None")
        self.status_label = QLabel("Status: Idle")

        self.btn_load_base = QPushButton("Select base SQLite (stripped)")
        self.btn_load_target = QPushButton("Select target SQLite (with symbols)")
        self.btn_run_match = QPushButton("Run Matching")
        self.btn_apply_rename = QPushButton("Apply rename in base DB")
        self.btn_cancel = QPushButton("Cancel Matching")
        self.btn_cancel.setEnabled(False)
        self.btn_apply_rename.setEnabled(False)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Base Addr", "Base Name", "Target Addr", "Target Name", "Match (%)"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)

        self.progress = QProgressBar()
        self.progress.setVisible(False)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self.btn_load_base)
        hlayout.addWidget(self.btn_load_target)
        hlayout.addWidget(self.btn_run_match)
        hlayout.addWidget(self.btn_cancel)
        hlayout.addWidget(self.btn_apply_rename)

        self.layout.addLayout(hlayout)
        self.layout.addWidget(self.label_base)
        self.layout.addWidget(self.label_target)
        self.layout.addWidget(self.status_label)
        self.layout.addWidget(self.table)
        self.layout.addWidget(self.progress)

        self.btn_load_base.clicked.connect(self.load_base)
        self.btn_load_target.clicked.connect(self.load_target)
        self.btn_run_match.clicked.connect(self.run_match)
        self.btn_cancel.clicked.connect(self.cancel_match)
        self.btn_apply_rename.clicked.connect(self.apply_rename)

        self.base_db = None
        self.target_db = None
        self.base_columns = {}
        self.target_columns = {}
        self.matches = []

        self.worker = None
        self.signals = WorkerSignals()

        self.signals.progress.connect(self.update_progress)
        self.signals.status.connect(self.update_status)
        self.signals.finished.connect(self.match_finished)
        self.signals.error.connect(self.match_error)
        self.signals.result.connect(self.match_result)

    def detect_columns(self, cursor):
        cursor.execute("PRAGMA table_info(functions)")
        cols = [row[1] for row in cursor.fetchall()]
        possible_names = {
            "address": ["address", "addr", "function_address"],
            "name": ["demangledName", "demangledNam", "name", "func_name", "function_name"],
            "hash": ["hexHash", "hash", "function_hash"]
        }
        detected = {}
        for key, candidates in possible_names.items():
            for c in candidates:
                if c in cols:
                    detected[key] = c
                    break
            else:
                detected[key] = None
        return detected

    def load_base(self):
        path, _ = QFileDialog.getOpenFileName(
            self.parent, "Select base SQLite (stripped)", "", "SQLite Files (*.sqlite *.db *.db3)"
        )
        if path:
            try:
                if self.base_db:
                    self.base_db.close()
                self.base_db = sqlite3.connect(path)
                cursor = self.base_db.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                print("Base DB - Tables:")
                for t in tables:
                    print(" -", t[0])
                self.base_columns = self.detect_columns(cursor)
                if not all(self.base_columns.values()):
                    raise Exception(f"Essential columns missing in base DB: {self.base_columns}")
                self.label_base.setText(f"Base DB: {path}")
                self.btn_apply_rename.setEnabled(False)
                self.clear_table()
            except Exception as e:
                QMessageBox.critical(self.parent, "Error", f"Failed to open base DB:\n{e}")

    def load_target(self):
        path, _ = QFileDialog.getOpenFileName(
            self.parent, "Select target SQLite (with symbols)", "", "SQLite Files (*.sqlite *.db *.db3)"
        )
        if path:
            try:
                if self.target_db:
                    self.target_db.close()
                self.target_db = sqlite3.connect(path)
                cursor = self.target_db.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                print("Target DB - Tables:")
                for t in tables:
                    print(" -", t[0])
                self.target_columns = self.detect_columns(cursor)
                if not all(self.target_columns.values()):
                    raise Exception(f"Essential columns missing in target DB: {self.target_columns}")
                self.label_target.setText(f"Target DB: {path}")
                self.btn_apply_rename.setEnabled(False)
                self.clear_table()
            except Exception as e:
                QMessageBox.critical(self.parent, "Error", f"Failed to open target DB:\n{e}")

    def clear_table(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        self.matches = []

    def check_tables(self, cursor):
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='functions'")
        return cursor.fetchone() is not None

    def get_functions(self, cursor, columns):
        address_col = columns["address"]
        name_col = columns["name"]
        hash_col = columns["hash"]
        query = f"SELECT {address_col}, {name_col}, {hash_col} FROM functions"
        cursor.execute(query)
        funcs = {}
        for addr, name, hsh in cursor.fetchall():
            funcs[addr] = {
                "name": name if name else "-",
                "hash": hsh if hsh else "",
            }
        return funcs

    def run_match(self):
        if self.worker and self.worker.is_alive():
            QMessageBox.warning(self.parent, "Warning", "Matching already running.")
            return

        if not self.base_db or not self.target_db:
            QMessageBox.warning(self.parent, "Warning", "Select both SQLite DBs first.")
            return

        base_cursor = self.base_db.cursor()
        target_cursor = self.target_db.cursor()

        if not self.check_tables(base_cursor):
            QMessageBox.critical(self.parent, "Error", "Table 'functions' not found in base DB.")
            return
        if not self.check_tables(target_cursor):
            QMessageBox.critical(self.parent, "Error", "Table 'functions' not found in target DB.")
            return

        base_funcs = self.get_functions(base_cursor, self.base_columns)
        target_funcs = self.get_functions(target_cursor, self.target_columns)

        self.clear_table()
        self.progress.setVisible(True)
        self.progress.setMaximum(len(base_funcs))
        self.progress.setValue(0)
        self.status_label.setText("Status: Starting matching...")

        self.worker = MatchWorker(base_funcs, target_funcs, self.signals)
        self.worker.start()
        self.btn_run_match.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_apply_rename.setEnabled(False)

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
            self.table.setItem(i, 0, QTableWidgetItem(addr_base_str))
            self.table.setItem(i, 1, QTableWidgetItem(b_name))
            self.table.setItem(i, 2, QTableWidgetItem(addr_target_str))
            self.table.setItem(i, 3, QTableWidgetItem(t_name))
            item_score = QTableWidgetItem(f"{score:.2f}")
            item_score.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 4, item_score)
        self.btn_apply_rename.setEnabled(True)
        self.status_label.setText(f"Status: Matching finished with {len(matches)} functions.")
        self.progress.setVisible(False)

    def apply_rename(self):
        if not self.base_db or not self.matches:
            QMessageBox.warning(self.parent, "Warning", "Nothing to rename.")
            return

        try:
            cursor = self.base_db.cursor()
            count_db = 0
            count_ida = 0
            col_name = self.base_columns.get("name", "demangledName")
            col_addr = self.base_columns.get("address", "address")

            for b_addr, b_name, t_addr, t_name, score in self.matches:
                if t_name != "-" and score > 0:
                    # Update the database
                    query = f"UPDATE functions SET {col_name} = ? WHERE {col_addr} = ?"
                    cursor.execute(query, (t_name, b_addr))
                    count_db += 1

                    # Rename in IDA if function exists at address
                    try:
                        addr_int = int(b_addr) if not isinstance(b_addr, int) else b_addr
                        if ida_funcs.get_func(addr_int):
                            if ida_name.set_name(addr_int, t_name, ida_name.SN_FORCE):
                                count_ida += 1
                    except Exception as e:
                        print(f"Error renaming function at {b_addr} in IDA: {e}")

            self.base_db.commit()
            QMessageBox.information(
                self.parent,
                "Rename Results",
                f"Renamed {count_db} functions in the base DB.\n"
                f"Renamed {count_ida} functions in IDA."
            )
            self.btn_apply_rename.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self.parent, "Rename Error", f"Error applying renames:\n{e}")

    def OnClose(self, form):
        if self.base_db:
            self.base_db.close()
        if self.target_db:
            self.target_db.close()


def main():
    form = DiaphoraForm()
    form.Show("SCRE - Renaming Helper")


if __name__ == "__main__":
    main()
