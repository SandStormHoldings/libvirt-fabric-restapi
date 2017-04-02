#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
filedesc: helper script to launch GameServer
'''

from noodles.app import startapp
from config import PORT,HOST

if __name__ == '__main__':
    startapp(port=PORT,host=HOST)
