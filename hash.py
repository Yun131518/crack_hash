import sys
import hashlib
import datetime
from functools import partial
from multiprocessing import Pool, cpu_count
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
    QFileDialog, QComboBox, QProgressBar, QTextEdit, QHBoxLayout
)
from PyQt6.QtCore import QThread, pyqtSignal

HASH_ALGOS = {
    'md5': 32,
    'sha1': 40,
    'sha256': 64,
    'sha512': 128,
}

def worker(args):
    hash_val, algo, lines_chunk = args
    for word in lines_chunk:
        word = word.strip()
        if not word:
            continue
        try:
            h = hashlib.new(algo, word.encode('utf-8')).hexdigest()
            if h == hash_val:
                return word
        except Exception:
            pass
    return None

class CrackThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    status_signal = pyqtSignal(str)

    def __init__(self, file_path, hash_val, algo=None):
        super().__init__()
        self.file_path = file_path
        self.hash_val = hash_val.lower()
        self.algo = algo
        self._is_running = True
        self.found = False
        self.pool = Pool(cpu_count())

    def run(self):
        self.found = False
        self._is_running = True

        possible_algos = [self.algo] if self.algo else []
        if not self.algo:
            length = len(self.hash_val)
            possible_algos = [k for k, v in HASH_ALGOS.items() if v == length]
            if not possible_algos:
                self.status_signal.emit("해시 길이에 맞는 알고리즘 후보 없음")
                self.finished_signal.emit()
                return

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                total_lines = sum(1 for _ in f)
        except Exception as e:
            self.status_signal.emit(f"파일 읽기 오류: {e}")
            self.finished_signal.emit()
            return

        chunk_size = 8000
        processed_lines = 0

        try:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                while self._is_running and not self.found:
                    lines = [f.readline() for _ in range(chunk_size)]
                    lines = list(filter(None, lines))
                    if not lines:
                        break

                    processed_lines += len(lines)
                    self.progress_signal.emit(int(processed_lines / total_lines * 100))

                    n_procs = cpu_count()
                    chunk_splits = [lines[i::n_procs] for i in range(n_procs)]

                    for algo in possible_algos:
                        args_list = [(self.hash_val, algo, chunk) for chunk in chunk_splits]
                        results = self.pool.map(worker, args_list)
                        for res in results:
                            if res:
                                self.found = True
                                self.result_signal.emit(f"알고리즘: {algo} 일치하는 단어: {res}")
                                break
                        if self.found:
                            break
            self.pool.close()
            self.pool.join()
        except Exception as e:
            self.status_signal.emit(f"작업 중 오류: {e}")

        if not self.found and self._is_running:
            self.status_signal.emit("일치하는 단어 없음")
        self.finished_signal.emit()

    def stop(self):
        self._is_running = False
        if self.pool:
            self.pool.terminate()
            self.pool.join()

class CrackApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("해시 크랙 도구 (PyQt6, 멀티프로세스, 직접 대조 포함)")
        self.resize(600, 450)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # 해시 입력
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("크랙할 해시값 입력 또는 붙여넣기")
        self.layout.addWidget(self.hash_input)

        # 워드리스트 파일 선택
        self.file_btn = QPushButton("워드리스트 파일 선택")
        self.file_btn.clicked.connect(self.select_file)
        self.layout.addWidget(self.file_btn)

        # 알고리즘 선택
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItem("자동 감지 (때려맞추기)")
        for algo in HASH_ALGOS.keys():
            self.hash_algo_combo.addItem(algo)
        self.layout.addWidget(self.hash_algo_combo)

        # 진행률 바
        self.progress_bar = QProgressBar()
        self.layout.addWidget(self.progress_bar)

        # 시작/중지 버튼
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("크랙 시작")
        self.start_btn.clicked.connect(self.start_crack)
        btn_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("중지")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_crack)
        btn_layout.addWidget(self.stop_btn)

        self.layout.addLayout(btn_layout)

        # 직접 대조 입력 & 버튼
        self.direct_check_input = QLineEdit()
        self.direct_check_input.setPlaceholderText("직접 추정할 단어 입력")
        self.layout.addWidget(self.direct_check_input)

        self.direct_check_btn = QPushButton("직접 대조")
        self.direct_check_btn.clicked.connect(self.direct_check)
        self.layout.addWidget(self.direct_check_btn)

        # 상태 라벨
        self.status_label = QLabel("대기 중")
        self.layout.addWidget(self.status_label)

        # 결과 출력
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.layout.addWidget(self.result_text)

        self.file_path = None
        self.thread = None
        self.log_file_path = "crack_log.txt"

    def log(self, message: str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "워드리스트 파일 선택", "", "텍스트 파일 (*.txt);;모든 파일 (*)")
        if path:
            self.file_path = path
            self.status_label.setText(f"선택된 파일: {path}")
            self.log(f"워드리스트 파일 선택됨: {path}")

    def start_crack(self):
        if not self.file_path:
            self.status_label.setText("워드리스트 파일을 먼저 선택하세요")
            return
        hash_val = self.hash_input.text().strip().lower()
        if not hash_val:
            self.status_label.setText("해시값을 입력하세요")
            return

        algo_text = self.hash_algo_combo.currentText()
        algo = None if algo_text == "자동 감지 (때려맞추기)" else algo_text

        self.status_label.setText(f"크랙 시작... (알고리즘: {algo_text})")
        self.progress_bar.setValue(0)
        self.result_text.clear()

        self.log(f"크랙 시작 - 파일: {self.file_path}, 해시: {hash_val}, 알고리즘: {algo_text}")

        self.thread = CrackThread(self.file_path, hash_val, algo)
        self.thread.progress_signal.connect(self.progress_bar.setValue)
        self.thread.result_signal.connect(self.on_result)
        self.thread.status_signal.connect(self.status_label.setText)
        self.thread.status_signal.connect(self.log)
        self.thread.finished_signal.connect(self.on_finished)

        self.thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_crack(self):
        if self.thread:
            self.thread.stop()
            self.status_label.setText("중지 중...")
            self.log("사용자에 의해 작업 중지됨")

    def direct_check(self):
        guess = self.direct_check_input.text().strip()
        if not guess:
            self.status_label.setText("비밀번호 추정값을 입력하세요")
            return
        hash_val = self.hash_input.text().strip().lower()
        if not hash_val:
            self.status_label.setText("크랙할 해시값을 입력하세요")
            return

        algo_text = self.hash_algo_combo.currentText()
        algo_list = []
        if algo_text == "자동 감지 (때려맞추기)":
            length = len(hash_val)
            algo_list = [k for k, v in HASH_ALGOS.items() if v == length]
            if not algo_list:
                self.status_label.setText("해시 길이에 맞는 알고리즘 후보 없음")
                return
        else:
            algo_list = [algo_text]

        matched = False
        for algo in algo_list:
            try:
                h = hashlib.new(algo, guess.encode('utf-8')).hexdigest()
                if h == hash_val:
                    matched = True
                    self.result_text.append(f"직접 대조 성공! 알고리즘: {algo}, 단어: {guess}")
                    self.log(f"직접 대조 성공 - 알고리즘: {algo}, 단어: {guess}")
                    break
            except Exception:
                pass
        if not matched:
            self.status_label.setText("직접 대조 실패")
            self.log(f"직접 대조 실패 - 단어: {guess}")

    def on_result(self, message):
        self.result_text.append(message)
        self.log(message)

    def on_finished(self):
        self.status_label.setText("작업 완료")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CrackApp()
    win.show()
    sys.exit(app.exec())
