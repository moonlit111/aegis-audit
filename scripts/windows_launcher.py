#!/usr/bin/env python3
"""Windows tray launcher, frozen with its own Python runtime for distribution."""
import argparse
import contextlib
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from types import SimpleNamespace
import webbrowser

from aegis import ROOT, environment
from configure_model import save_settings
import manage


class BasicLimits(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                ('flags', w.DWORD), ('minimum_ws', ctypes.c_size_t),
                ('maximum_ws', ctypes.c_size_t), ('active_limit', w.DWORD),
                ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [('basic', BasicLimits), ('io', IoCounters),
                ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]


class ThreadEntry(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('thread_id', w.DWORD),
                ('process_id', w.DWORD), ('base_priority', w.LONG),
                ('delta_priority', w.LONG), ('flags', w.DWORD)]


class Windows:
    def __init__(self):
        if os.name != 'nt':
            raise RuntimeError('The desktop launcher requires Windows.')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.user = ctypes.WinDLL('user32', use_last_error=True)
        signatures = {
            'CreateMutexW': (w.HANDLE, [ctypes.c_void_p, w.BOOL, w.LPCWSTR]),
            'CreateEventW': (w.HANDLE, [ctypes.c_void_p, w.BOOL, w.BOOL, w.LPCWSTR]),
            'OpenEventW': (w.HANDLE, [w.DWORD, w.BOOL, w.LPCWSTR]),
            'SetEvent': (w.BOOL, [w.HANDLE]),
            'WaitForSingleObject': (w.DWORD, [w.HANDLE, w.DWORD]),
            'CloseHandle': (w.BOOL, [w.HANDLE]),
            'CreateJobObjectW': (w.HANDLE, [ctypes.c_void_p, w.LPCWSTR]),
            'SetInformationJobObject': (w.BOOL, [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]),
            'AssignProcessToJobObject': (w.BOOL, [w.HANDLE, w.HANDLE]),
            'CreateToolhelp32Snapshot': (w.HANDLE, [w.DWORD, w.DWORD]),
            'Thread32First': (w.BOOL, [w.HANDLE, ctypes.POINTER(ThreadEntry)]),
            'Thread32Next': (w.BOOL, [w.HANDLE, ctypes.POINTER(ThreadEntry)]),
            'OpenThread': (w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
            'ResumeThread': (w.DWORD, [w.HANDLE]),
            'GetConsoleWindow': (w.HWND, []),
            'AllocConsole': (w.BOOL, []),
            'FreeConsole': (w.BOOL, []),
            'SetDllDirectoryW': (w.BOOL, [w.LPCWSTR]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = result, arguments
        self.user.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
        self.user.MessageBoxW.argtypes = [w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT]

    def require(self, result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def message(self, message):
        self.user.MessageBoxW(None, str(message)[:3000], 'AegisAudit', 0x10)


class ProcessOwner:
    def __init__(self, windows, job_name=None):
        self.windows = windows
        self.children = []
        self.job_name = job_name
        self.handle = windows.require(windows.kernel.CreateJobObjectW(None, job_name))
        if job_name and ctypes.get_last_error() == 183:
            windows.kernel.CloseHandle(self.handle)
            self.handle = None
            raise RuntimeError('The new process owner name is already in use.')
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            windows.require(windows.kernel.SetInformationJobObject(
                self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        except BaseException:
            windows.kernel.CloseHandle(self.handle)
            self.handle = None
            raise

    def spawn(self, args, **kwargs):
        # Assign the suspended process before it can create any descendants.
        kwargs['creationflags'] = kwargs.get('creationflags', 0) | 0x4 | subprocess.CREATE_NEW_PROCESS_GROUP
        if self.job_name:
            kwargs['env'] = dict(kwargs.get('env') or os.environ)
            kwargs['env']['AEGIS_DESKTOP_JOB'] = self.job_name
        child = subprocess.Popen(args, **kwargs)
        kernel = self.windows.kernel
        try:
            self.windows.require(kernel.AssignProcessToJobObject(self.handle, int(child._handle)))
            snapshot = kernel.CreateToolhelp32Snapshot(0x4, 0)
            if snapshot == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                entry = ThreadEntry()
                entry.size = ctypes.sizeof(entry)
                found = kernel.Thread32First(snapshot, ctypes.byref(entry))
                resumed = False
                while found:
                    if entry.process_id == child.pid:
                        thread = self.windows.require(kernel.OpenThread(0x2, False, entry.thread_id))
                        try:
                            resumed = kernel.ResumeThread(thread) != 0xffffffff
                        finally:
                            kernel.CloseHandle(thread)
                        break
                    found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
                if not resumed:
                    raise RuntimeError('Cannot resume the owned application process.')
            finally:
                kernel.CloseHandle(snapshot)
            self.children.append(child)
            return child
        except BaseException:
            child.kill()
            child.wait(timeout=10)
            raise

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                try:
                    child.send_signal(signal.CTRL_BREAK_EVENT)
                    child.wait(timeout=25)
                except (OSError, subprocess.TimeoutExpired):
                    logging.warning('Graceful stop timed out for owned process %s; closing its job.', child.pid)
        if self.handle:
            self.windows.kernel.CloseHandle(self.handle)
            self.handle = None
        for child in self.children:
            child.wait(timeout=10)
        if manage.STATE.is_file():
            state = json.loads(manage.STATE.read_text(encoding='utf-8'))
            recorded = {item['pid'] for item in state['processes']}
            if recorded == {child.pid for child in self.children}:
                manage.STATE.unlink()
        logging.info('Owned server and executor have stopped.')


def instance_names(root=ROOT):
    identity = hashlib.sha256(str(root.resolve()).lower().encode('utf-8')).hexdigest()[:24]
    return 'Global\\AegisAudit-' + identity, 'Global\\AegisAudit-stop-' + identity


def choose_port(preferred=None):
    ports = [preferred] if preferred is not None else range(7331, 7352)
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError('Port must be between 1 and 65535.')
        try:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError('The local port is in use. Choose a different --port.')


def existing_url():
    if not manage.STATE.is_file():
        return None
    state = json.loads(manage.STATE.read_text(encoding='utf-8'))
    if any(manage.owned(item) for item in state['processes']):
        return state['url']
    return None


def configure_dialog():
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk

    class ModelDialog(simpledialog.Dialog):
        def body(self, master):
            ttk.Label(master, text='模型').grid(row=0, column=0, padx=8, pady=8, sticky='w')
            self.model = ttk.Entry(master, width=40)
            self.model.insert(0, 'deepseek-v4-flash')
            settings = manage.DATA / 'server/model.json'
            if settings.is_file():
                self.model.delete(0, tk.END)
                self.model.insert(0, json.loads(settings.read_text(encoding='utf-8'))['model'])
            self.model.grid(row=0, column=1, padx=8, pady=8)
            ttk.Label(master, text='API 密钥').grid(row=1, column=0, padx=8, pady=8, sticky='w')
            self.key = ttk.Entry(master, width=40, show='*')
            self.key.grid(row=1, column=1, padx=8, pady=8)
            return self.key

        def buttonbox(self):
            buttons = ttk.Frame(self)
            ttk.Button(buttons, text='保存', command=self.ok).pack(side=tk.LEFT, padx=6, pady=10)
            ttk.Button(buttons, text='取消', command=self.cancel).pack(side=tk.LEFT, padx=6, pady=10)
            buttons.pack()
            self.bind('<Return>', self.ok)
            self.bind('<Escape>', self.cancel)

        def validate(self):
            try:
                save_settings(manage.DATA / 'server', self.key.get(), self.model.get())
                return True
            except (ValueError, OSError) as error:
                messagebox.showerror('DeepSeek', str(error), parent=self)
                return False

    parent = tk.Tk()
    parent.withdraw()
    try:
        parent.iconbitmap(str(ROOT / 'tools/windows/aegis.ico'))
        ModelDialog(parent, 'DeepSeek 模型配置')
    finally:
        parent.destroy()


def tray(windows, stop_event, owner, url, no_open):
    import pystray
    from PIL import Image

    def show_settings(icon, item):
        try:
            configure_dialog()
        except Exception as error:
            logging.exception('Model configuration dialog failed')
            windows.message(error)

    def request_stop(icon, item):
        windows.kernel.SetEvent(stop_event)

    menu = pystray.Menu(
        pystray.MenuItem('打开 AegisAudit', lambda: webbrowser.open(url), default=True),
        pystray.MenuItem('DeepSeek 模型配置', show_settings),
        pystray.MenuItem('打开日志目录', lambda: os.startfile(manage.DATA / 'logs')),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('退出 AegisAudit', request_stop),
    )
    with Image.open(ROOT / 'tools/windows/aegis.ico') as source:
        icon = pystray.Icon('AegisAudit', source.copy(), 'AegisAudit 0.2.0', menu)

    def watch():
        while windows.kernel.WaitForSingleObject(stop_event, 1000) == 258:
            if any(child.poll() is not None for child in owner.children):
                logging.error('A managed application process exited unexpectedly.')
                windows.kernel.SetEvent(stop_event)
                break
        icon.stop()

    def setup(icon):
        icon.visible = True
        threading.Thread(target=watch, daemon=True).start()
        if not no_open:
            webbrowser.open(url)

    logging.info('Tray ready at %s', url)
    icon.run(setup=setup)


def run(options, windows):
    mutex_name, event_name = instance_names()
    if options.stop:
        event = windows.kernel.OpenEventW(0x2, False, event_name)
        if event:
            try:
                windows.require(windows.kernel.SetEvent(event))
            finally:
                windows.kernel.CloseHandle(event)
        return 0
    if options.diagnostics:
        result = subprocess.run([str(manage.executable('aegis-executor')), '--doctor'],
                                cwd=ROOT, env=environment(), capture_output=True, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        options.diagnostics.parent.mkdir(parents=True, exist_ok=True)
        options.diagnostics.write_bytes(result.stdout)
        return 0
    if options.configure_model:
        configure_dialog()
        return 0
    mutex = windows.require(windows.kernel.CreateMutexW(None, True, mutex_name))
    duplicate = ctypes.get_last_error() == 183
    stop_event = None
    owner = None
    private_console = False
    try:
        if duplicate:
            for _ in range(100):
                if manage.STATE.is_file():
                    url = existing_url()
                    if url:
                        if not options.no_open:
                            webbrowser.open(url)
                        return 0
                time.sleep(0.1)
            raise RuntimeError('Another AegisAudit instance is starting or stopping.')
        url = existing_url()
        if url:
            if not options.no_open:
                webbrowser.open(url)
            return 0
        stop_event = windows.require(windows.kernel.CreateEventW(None, True, False, event_name))
        if not windows.kernel.GetConsoleWindow():
            windows.require(windows.kernel.AllocConsole())
            private_console = True
            windows.user.ShowWindow(windows.kernel.GetConsoleWindow(), 0)
        owner = ProcessOwner(windows, mutex_name + '-job-' + uuid.uuid4().hex)
        port = choose_port(options.port)
        manage.start(SimpleNamespace(port=port, open=False), process_factory=owner.spawn)
        tray(windows, stop_event, owner, f'http://127.0.0.1:{port}', options.no_open)
        return 0
    finally:
        try:
            if owner:
                owner.close()
        finally:
            if stop_event:
                windows.kernel.CloseHandle(stop_event)
            windows.kernel.CloseHandle(mutex)
            if private_console:
                windows.kernel.FreeConsole()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int)
    parser.add_argument('--no-open', action='store_true')
    parser.add_argument('--non-interactive', action='store_true')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--stop', action='store_true')
    actions.add_argument('--configure-model', action='store_true')
    actions.add_argument('--diagnostics', type=Path)
    options = parser.parse_args()
    windows = Windows()
    try:
        (manage.DATA / 'logs').mkdir(parents=True, exist_ok=True)
        with (manage.DATA / 'logs/desktop.log').open('a', encoding='utf-8', buffering=1) as log:
            logging.basicConfig(stream=log, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
            with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                # Do not let PyInstaller's DLL search directory affect native tools.
                if getattr(sys, 'frozen', False):
                    import tkinter
                    from PIL import Image
                    windows.require(windows.kernel.SetDllDirectoryW(None))
                try:
                    return run(options, windows)
                except Exception:
                    logging.exception('Windows launcher failed')
                    raise
    except Exception as error:
        if not options.non_interactive:
            windows.message(error)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
