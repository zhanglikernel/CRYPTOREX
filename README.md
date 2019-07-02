# CryptoREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices
CryptoREX is a firmware analysis tool to detect crypto misuse in IoT devices. Now it supports multiple architetures, including ARM, MIPS, MIPSel, etc.
# Prerequisites
1. Linux. We tested Ubuntu 16.04. 
2. IDA Pro. We tested version 6.4.
3. Python. We tested version 2.7.4.
# How to use
python bin2vex.py <firmware_path>(input_dir) <firmware_decompressed_path>(middle_dir) <firmware_IR_PATH>(middle_dir) <detail_report_path>(output_dir) <summary_report_dir>(output_dir)
# How to cite
Li Zhang, Jiongyi Chen, Wenrui Diao, Shanqing Guo, Jian Weng, and Kehuan Zhang. CryptoREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices. The 22nd International Symposium on Research in Attacks, Intrusions and Defenses (RAID), Beijing, China. September, 2019.
