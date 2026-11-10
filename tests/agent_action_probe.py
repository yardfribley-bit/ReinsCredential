"""Synthetic-only action for real Agent acceptance. Run inside its test workspace."""
import hashlib
import json
import os
import pathlib
import socket
import time

root = pathlib.Path(__file__).resolve().parent
config = json.loads((root / "coordinator.json").read_text())
proof = {"run_id": config["run_id"], "label": config["label"], "pid": os.getpid(),
         "ppid": os.getppid(), "started_us": time.time_ns() // 1000}
with (root / "synthetic.env").open("rb") as file:
    proof["sha256"] = hashlib.sha256(file.read()).hexdigest()
    connection = socket.socket()
    connection.settimeout(2)
    try:
        connection.connect(("127.0.0.1", config["port"]))
        connection.sendall(json.dumps({"run_id": config["run_id"], "label": config["label"]}).encode())
        proof["loopback_connected"] = True
    except OSError as error:
        proof["loopback_connected"] = False
        proof["loopback_error"] = type(error).__name__
    (root / "proof.json").write_text(json.dumps(proof))
    # Deliberately long enough for best-effort polling; not a claim about short reads.
    time.sleep(12)
    connection.close()
proof["completed_us"] = time.time_ns() // 1000
(root / "proof.json").write_text(json.dumps(proof))
print(json.dumps(proof))
