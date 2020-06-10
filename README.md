# scanner
web information scanner
# 功能
- 1.whois查询
- 2.子域名查询&导出
- 3.IP查询（CDN查询/IP查询/IP localtion查询）
- 4.端口及服务查询
# 环境
Django&python3
# python库
- import socket
- import tld
- import re
- import requests
- from bs4 import BeautifulSoup
- import xlwt
- import sys
- import warnings,logging
- warnings.filterwarnings("ignore", category=DeprecationWarning)
- logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
- from scapy.all import *
- from threading import Thread
- import queue
- import nmap
