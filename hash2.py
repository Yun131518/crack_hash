import sys
import hashlib
import datetime
from functools import partial
from multiprocessing import Pool, cpu_count
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
    QFileDialog, QComboBox, QProgressBar, QTextEdit, QHBoxLayout, QRadioButton, QButtonGroup
)
from PyQt6.QtCore import QThread, pyqtSignal
import subprocess
import threading
import os

HASH_ALGOS = {
    'md5': 32,
    'sha1': 40,
    'sha256': 64,
    'sha512': 128,
}

HASHCAT_MODES = {
    'md5': 0,
    'sha1': 100,
    'sha256': 1400,
    'sha512': 1700,
}

# --- hashlib 워드리스트 크랙 워커 ---
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

# --- 멀티프로세스 워드리스트 크랙 스레드 ---
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
                                self.result_signal.emit(f"내장 크랙 성공! 알고리즘: {algo}, 단어: {res}")
                                break
                        if self.found:
                            break
            self.pool.close()
            self.pool.join()
        except Exception as e:
            self.status_signal.emit(f"작업 중 오류: {e}")

        if not self.found and self._is_running:
            self.status_signal.emit("내장 크랙 실패: 일치하는 단어 없음")
        self.finished_signal.emit()

    def stop(self):
        self._is_running = False
        if self.pool:
            self.pool.terminate()
            self.pool.join()

# --- Hashcat 외부 프로세스 실행 스레드 ---
class HashcatThread(QThread):
    output_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    status_signal = pyqtSignal(str)

    def __init__(self, hashcat_path, hash_val, wordlist_file, hash_algo):
        super().__init__()
        self.hashcat_path = hashcat_path
        self.hash_val = hash_val
        self.wordlist_file = wordlist_file
        self.hash_algo = hash_algo
        self._stop_event = threading.Event()
        self.process = None

    def run(self):
        if not os.path.isfile(self.hashcat_path):
            self.status_signal.emit("Hashcat 실행 파일 경로가 올바르지 않습니다.")
            self.finished_signal.emit()
            return

        # 해시 값을 임시 파일에 저장 (Hashcat은 파일에서 해시를 읽음)
        try:
            with open("temp_hash.txt", "w", encoding="utf-8") as f:
                f.write(self.hash_val + "\n")
        except Exception as e:
            self.status_signal.emit(f"해시 파일 생성 오류: {e}")
            self.finished_signal.emit()
            return

        # Hashcat 모드 선택
        mode = HASHCAT_MODES.get(self.hash_algo)
        if mode is None:
            self.status_signal.emit(f"Hashcat이 지원하지 않는 알고리즘입니다: {self.hash_algo}")
            self.finished_signal.emit()
            return

        cmd = [
            self.hashcat_path,
            "-m", str(mode),
            "temp_hash.txt",
            self.wordlist_file,
            "--quiet",
            "--show"
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
        except Exception as e:
            self.status_signal.emit(f"Hashcat 실행 오류: {e}")
            self.finished_signal.emit()
            return

        self.status_signal.emit("Hashcat 크랙 시작...")

        while True:
            if self._stop_event.is_set():
                if self.process:
                    self.process.terminate()
                self.status_signal.emit("Hashcat 크랙 중지됨")
                break

            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_signal.emit(output.strip())

        self.finished_signal.emit()

    def stop(self):
        self._stop_event.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

# --- 메인 UI 클래스 ---
class CrackApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("해시 크랙 도구 (PyQt6, 멀티프로세스, 직접 대조, Hashcat 통합)")
        self.resize(700, 600)

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

        self.file_label = QLabel("선택된 워드리스트 파일: 없음")
        self.layout.addWidget(self.file_label)

        # 해시 알고리즘 선택
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItem("자동 감지 (때려맞추기)")
        for algo in HASH_ALGOS.keys():
            self.hash_algo_combo.addItem(algo)
        self.layout.addWidget(self.hash_algo_combo)

        # 실행 방식 선택 라디오 버튼
        self.method_group = QButtonGroup()
        self.rb_builtin = QRadioButton("내장 멀티프로세스 크랙 (hashlib)")
        self.rb_direct = QRadioButton("직접 대조 (입력값 대조)")
        self.rb_hashcat = QRadioButton("Hashcat 연동 크랙 (외부 실행)")
        self.rb_builtin.setChecked(True)

        self.layout.addWidget(self.rb_builtin)
        self.layout.addWidget(self.rb_direct)
        self.layout.addWidget(self.rb_hashcat)

        # Hashcat 실행파일 경로 입력 및 선택 버튼
        hcat_layout = QHBoxLayout()
        self.hashcat_path_input = QLineEdit()
        self.hashcat_path_input.setPlaceholderText("Hashcat 실행파일 경로 (hashcat.exe 등)")
        hcat_layout.addWidget(self.hashcat_path_input)
        self.hashcat_path_btn = QPushButton("Hashcat 실행파일 선택")
        self.hashcat_path_btn.clicked.connect(self.select_hashcat_path)
        hcat_layout.addWidget(self.hashcat_path_btn)
        self.layout.addLayout(hcat_layout)

        # 직접 대조 입력란
        self.direct_input = QLineEdit()
        self.direct_input.setPlaceholderText("직접 대조할 평문 입력")
        self.layout.addWidget(self.direct_input)

        # 진행률 표시
        self.progress_bar = QProgressBar()
        self.layout.addWidget(self.progress_bar)

        # 상태 출력 라벨
        self.status_label = QLabel("대기 중...")
        self.layout.addWidget(self.status_label)

        # 로그 텍스트창
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.layout.addWidget(self.log_text)

        # 시작 / 중지 버튼
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("시작")
        self.stop_btn = QPushButton("중지")
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        self.layout.addLayout(btn_layout)

        # 버튼 시그널 연결
        self.start_btn.clicked.connect(self.start_crack)
        self.stop_btn.clicked.connect(self.stop_crack)

        # 크랙 스레드 초기값
        self.crack_thread = None
        self.hashcat_thread = None

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "워드리스트 파일 선택", "", "텍스트 파일 (*.txt);;모든 파일 (*)")
        if file_path:
            self.file_label.setText(f"선택된 워드리스트 파일: {file_path}")
            self.wordlist_path = file_path

    def select_hashcat_path(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Hashcat 실행파일 선택", "", "실행 파일 (*.exe);;모든 파일 (*)")
        if file_path:
            self.hashcat_path_input.setText(file_path)

    def log(self, msg):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{now}] {msg}")

    def start_crack(self):
        self.log_text.clear()
        hash_val = self.hash_input.text().strip().lower()
        if not hash_val:
            self.status_label.setText("해시값을 입력하세요.")
            return

        selected_algo = self.hash_algo_combo.currentText()
        if selected_algo == "자동 감지 (때려맞추기)":
            algo = None
        else:
            algo = selected_algo

        method = None
        if self.rb_builtin.isChecked():
            method = "builtin"
        elif self.rb_direct.isChecked():
            method = "direct"
        elif self.rb_hashcat.isChecked():
            method = "hashcat"

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("작업 시작...")

        # 직접 대조 방식
        if method == "direct":
            plain = self.direct_input.text()
            if not plain:
                self.status_label.setText("직접 대조할 평문을 입력하세요.")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return

            try:
                h = hashlib.new(algo if algo else 'md5', plain.encode('utf-8')).hexdigest()
            except Exception:
                self.status_label.setText("알고리즘 오류 또는 지원 안됨")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return

            if h == hash_val:
                self.log("직접 대조 성공: 입력 평문과 해시가 일치합니다.")
                self.status_label.setText("직접 대조 성공!")
            else:
                self.log("직접 대조 실패: 입력 평문과 해시가 일치하지 않습니다.")
                self.status_label.setText("직접 대조 실패")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.progress_bar.setValue(100)
            return

        # 내장 크랙
        if method == "builtin":
            if not hasattr(self, 'wordlist_path'):
                self.status_label.setText("워드리스트 파일을 선택하세요.")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return
            self.crack_thread = CrackThread(self.wordlist_path, hash_val, algo)
            self.crack_thread.progress_signal.connect(self.progress_bar.setValue)
            self.crack_thread.result_signal.connect(self.on_result)
            self.crack_thread.status_signal.connect(self.on_status)
            self.crack_thread.finished_signal.connect(self.on_finished)
            self.crack_thread.start()
            self.status_label.setText("내장 멀티프로세스 크랙 실행 중...")

        # Hashcat 연동
        if method == "hashcat":
            if not hasattr(self, 'wordlist_path'):
                self.status_label.setText("워드리스트 파일을 선택하세요.")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return
            hashcat_path = self.hashcat_path_input.text()
            if not hashcat_path:
                self.status_label.setText("Hashcat 실행파일 경로를 입력하세요.")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return
            if algo is None:
                self.status_label.setText("Hashcat은 해시 알고리즘 선택이 필요합니다.")
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                return

            self.hashcat_thread = HashcatThread(hashcat_path, hash_val, self.wordlist_path, algo)
            self.hashcat_thread.output_signal.connect(self.on_hashcat_output)
            self.hashcat_thread.status_signal.connect(self.on_status)
            self.hashcat_thread.finished_signal.connect(self.on_finished)
            self.hashcat_thread.start()
            self.status_label.setText("Hashcat 크랙 실행 중...")

    def stop_crack(self):
        if self.crack_thread and self.crack_thread.isRunning():
            self.crack_thread.stop()
        if self.hashcat_thread and self.hashcat_thread.isRunning():
            self.hashcat_thread.stop()
        self.status_label.setText("작업 중지됨")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(0)

    def on_result(self, text):
        self.log(text)
        self.status_label.setText("크랙 성공!")

    def on_status(self, text):
        self.log(text)
        self.status_label.setText(text)

    def on_finished(self):
        self.status_label.setText("작업 완료")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        # temp_hash.txt 삭제
        if os.path.exists("temp_hash.txt"):
            try:
                os.remove("temp_hash.txt")
            except Exception:
                pass

    def on_hashcat_output(self, text):
        self.log(f"[Hashcat] {text}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CrackApp()
    win.show()
    sys.exit(app.exec())
