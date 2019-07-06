# CryptoREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices
CryptoREX is a firmware analysis tool to detect crypto misuses in IoT devices. Now it supports multiple architetures, including ARM, MIPS, MIPSel, etc.
# Prerequisites
1. IDA Pro. We tested version 6.4.
2. Python. We tested version 2.7.4.
3. angr
# How to use
python bin2vex.py <firmware_path>(input_dir) <firmware_decompressed_path>(middle_dir) <firmware_IR_PATH>(middle_dir) <detail_report_path>(output_dir) <summary_report_dir>(output_dir)
# How to cite
Li Zhang, Jiongyi Chen, [Wenrui Diao](https://diaowenrui.github.io/), [Shanqing Guo](http://faculty.sdu.edu.cn/guoshanqing/zh_CN/), [Jian Weng](https://xxxy2016.jnu.edu.cn/Item/1534.aspx), and [Kehuan Zhang](https://staff.ie.cuhk.edu.hk/~khzhang/). CryptoREX: Large-scale Analysis of Cryptographic Misuse in IoT Devices. The 22nd International Symposium on Research in Attacks, Intrusions and Defenses (RAID), Beijing, China. September, 2019.
# Paper Abstract
Cryptographic functions play a critical role in the secure transmission and storage of application data. Although most crypto functions are well-defined and carefully-implemented in standard libraries, in practice, they could be easily misused or incorrectly encapsulated due to its error-prone nature and inexperience of developers. This situation is even worse in the IoT domain, given that developers tend to sacrifice security for performance in order to suit resource-constrained IoT devices. Given the severity and the pervasiveness of such bad practice, it is crucial to raise public awareness about this issue, find the misuses and shed light on best practices.

In this paper, we design and implement CryptoREX, a framework to identify crypto misuse of IoT devices under diverse architectures and in a scalable manner. In particular, CryptoREX lifts binary code to a unified IR and performs static taint analysis across multiple executables. To aggres- sively capture and identify the misuses of self-defined crypto APIs, CryptoREX dynamically updates the API list during taint analysis and automatically tracks the function arguments. Running on 521 firmware images with 165 pre-defined crypto APIs, it successfully discovered 679 crypto misuse issues in total, which on average costs only 1120 seconds per firmware. Our study shows 24.2% of firmware images violates at least one misuse rule, and most of the discovered misuses are un- known before. The misuses could result in sensitive data leakage, authentication bypass, password brute-force, and etc. Our findings highlight the poor implementation and weak protection in today’s IoT development.
