import sys
import hashlib
import time
from queue import PriorityQueue
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QProgressBar, QTextEdit, QComboBox
)
from PyQt5.QtCore import Qt, QThreadPool, QRunnable, pyqtSignal, QObject


class WorkerSignals(QObject):
    progress = pyqtSignal(int)
    result = pyqtSignal(str)
    finished = pyqtSignal()


class CrackWorker(QRunnable):
    def __init__(self, file_path, hash_value, algo, priority, signals):
        super().__init__()
        self.file_path = file_path
        self.hash_value = hash_value
        self.algo = algo
        self.priority = priority
        self.signals = signals

    def run(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)
                count = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    password = line.strip()
                    hashed = hashlib.new(self.algo, password.encode()).hexdigest()
                    if hashed == self.hash_value:
                        self.signals.result.emit(f"[✔] {self.file_path} 비밀번호 찾음: {password}")
                        self.signals.finished.emit()
                        return
                    count += 1
                    if count % 1000 == 0:
                        pos = f.tell()
                        progress = int(pos / file_size * 100)
                        self.signals.progress.emit(progress)
            self.signals.result.emit(f"[✘] {self.file_path}에서 일치하는 비밀번호를 찾지 못했습니다.")
        except Exception as e:
            self.signals.result.emit(f"[!] 오류 발생 ({self.file_path}): {e}")
        self.signals.finished.emit()


class HashCrackerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("멀티 워드리스트 해시 크래커")
        self.setGeometry(500, 300, 600, 400)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("해시 값 입력:"))
        self.hash_input = QLineEdit()
        layout.addWidget(self.hash_input)

        layout.addWidget(QLabel("해시 종류 선택:"))
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(["md5", "sha1", "sha256", "sha512"])
        layout.addWidget(self.hash_combo)

        self.add_wordlist_btn = QPushButton("워드리스트 추가 (우선순위 설정 가능)")
        self.add_wordlist_btn.clicked.connect(self.add_wordlist)
        layout.addWidget(self.add_wordlist_btn)

        self.start_btn = QPushButton("크랙 시작")
        self.start_btn.clicked.connect(self.start_crack)
        layout.addWidget(self.start_btn)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        layout.addWidget(QLabel("로그 및 결과:"))
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

        self.threadpool = QThreadPool()
        self.task_queue = PriorityQueue()
        self.current_worker = None
        self.total_tasks = 0
        self.completed_tasks = 0

        self.wordlists = []  # (priority, file_path)

        # 로그 파일 오픈
        self.log_file = open("cracker_log.txt", "a", encoding='utf-8')

    def add_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "워드리스트 선택", "", "Text Files (*.txt);;All Files (*)")
        if path:
            # 우선순위 입력 받기 (간단히 dialog 대체, 여기서는 1 고정)
            priority = 1  # 필요시 GUI로 받도록 확장 가능
            self.wordlists.append((priority, path))
            self.log(f"워드리스트 추가됨 (우선순위 {priority}): {path}")

    def log(self, message):
        timestamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        self.log_output.append(f"{timestamp} {message}")
        self.log_file.write(f"{timestamp} {message}\n")
        self.log_file.flush()

    def start_crack(self):
        if not self.wordlists:
            self.log("워드리스트가 없습니다!")
            return
        hash_val = self.hash_input.text().strip().lower()
        if not hash_val:
            self.log("해시 값을 입력하세요!")
            return

        algo = self.hash_combo.currentText()
        self.total_tasks = len(self.wordlists)
        self.completed_tasks = 0
        self.progress.setValue(0)

        # 정렬 후 큐에 넣기
        for prio, wl_path in sorted(self.wordlists):
            self.task_queue.put((prio, wl_path))

        self.log("크랙 작업 시작")
        self.run_next_task(hash_val, algo)

    def run_next_task(self, hash_val, algo):
        if self.task_queue.empty():
            self.log("모든 작업 완료")
            self.progress.setValue(100)
            return

        prio, wl_path = self.task_queue.get()
        self.log(f"작업 시작: {wl_path} (우선순위 {prio})")

        signals = WorkerSignals()
        signals.progress.connect(self.progress.setValue)
        signals.result.connect(self.log)
        signals.finished.connect(lambda: self.on_task_finished(hash_val, algo))

        worker = CrackWorker(wl_path, hash_val, algo, prio, signals)
        self.current_worker = worker
        self.threadpool.start(worker)

    def on_task_finished(self, hash_val, algo):
        self.completed_tasks += 1
        total = self.total_tasks
        self.progress.setValue(int(self.completed_tasks / total * 100))
        self.run_next_task(hash_val, algo)

    def closeEvent(self, event):
        self.log_file.close()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HashCrackerGUI()
    window.show()
    sys.exit(app.exec_())
