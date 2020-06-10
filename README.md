# scanner
web information scanner
# 环境
Django&python3
# python库
import socket
import tld
import re
import requests
from bs4 import BeautifulSoup
#import bs4 #使用标签类型定义
import xlwt
import sys
import warnings,logging
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import Thread
import queue
import nmap
