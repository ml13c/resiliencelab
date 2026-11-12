@echo off
scp %1 qnxpi:~/bin/ && ssh qnxpi "chmod +x ~/bin/%~nx1"