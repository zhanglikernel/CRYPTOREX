# CRYPTOREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices
CRYPTOREX is a firmware analysis tool to detect crypto misuse in IoT device. Now we support multi-architeture, including ARM, MIPS, MIPSel, etc.
# Prerequisites
1. You need to download IDA pro. We tested version 6.4.
2. You need a python(2.7.4) installed.
# How to use
python bin2vex.py <firmware_path>(input_dir) <firmware_decompressed_path>(middle_dir) <firmware_IR_PATH>(middle_dir) <detail_report_path>(output_dir) <summary_report_dir>(output_dir)
