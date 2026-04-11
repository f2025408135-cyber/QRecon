OPENQASM 2.0;
include "qelib1.inc";
qreg q[5];
creg c[5];
rx(0.1) q[0]; rx(0.2) q[1]; rx(0.3) q[2]; rx(0.4) q[3]; rx(0.5) q[4];
ry(0.1) q[0]; ry(0.2) q[1]; ry(0.3) q[2]; ry(0.4) q[3]; ry(0.5) q[4];
measure q[0] -> c[0]; measure q[1] -> c[1]; measure q[2] -> c[2];
measure q[3] -> c[3]; measure q[4] -> c[4];
