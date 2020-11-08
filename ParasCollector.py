#!/usr/bin/env python
#coding=utf8

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

import os
import json


# 定义保存域名，参数，URL 的类
class LogEntry:
    def __init__(self, host, paras):
        self._host = host
        self._count = len(paras)
        self._paras = paras

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._parasViewer.setText(logEntry._paras)
        # self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    


class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse, ITab, IMessageEditorController, AbstractTableModel):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('ParasCollector')
        self._log = ArrayList()
        self._lock = Lock()

        # 主窗口
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # 详情
        tabs = JTabbedPane()
        self._parasViewer = callbacks.createTextEditor()
        tabs.addTab("Paras",self._parasViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # 定义 UI 组件
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        # 将 UI 组件添加到 BURP 的 UI
        callbacks.addSuiteTab(self)


        # 注册功能
        callbacks.registerHttpListener(self)

        return


    def getTabCaption(self):
        return "ParasCollector"
    
    def getUiComponent(self):
        return self._splitpane
        

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 4:
            # 读 json 文件取得数据
            self._lock.acquire() # 加锁，反应会慢一点
            try:
                with open("allparas.json","r") as f:
                    allparas = json.loads(f.read())
            except Exception as ex:
                allparas = {}
                print("shit!!\n")
                print("%s"%ex)

            host = messageInfo.getHttpService().getHost().encode('utf-8')
            paras = allparas.get(host)
            if paras == None:
                paras = []
            if messageIsRequest: # 如果是一个请求
                request = messageInfo.getRequest() # 获得请求信息
                analyzedRequest = self._helpers.analyzeRequest(request)
                paras1 = analyzedRequest.getParameters()
                for para in paras1:
                    temp = str(para.getName())
                    if temp not in paras: # 去重
                            paras.append(temp)
                if paras !=[]:
                    paras.sort()
                    allparas[host] = paras
            if not messageIsRequest: # 如果是个响应
                response = messageInfo.getResponse() # 获得响应信息
                analyzedResponse = self._helpers.analyzeResponse(response)
                if analyzedResponse.getInferredMimeType() == "JSON":
                    body = response[analyzedResponse.getBodyOffset():].tostring() # 获取返回包
                    paras2 = json.loads(body).keys()
                    for para in paras2:
                        if para not in paras: # 去重
                            paras.append(str(para))
                if paras !=[]:
                    paras.sort()
                    allparas[host] = paras
            if allparas != {}:
                with open("allparas.json","w+") as f:
                    json.dump(allparas, f, ensure_ascii=False)
            
            row = self._log.size()
            self._log.clear()
            for host in allparas.keys():
                self._log.add(LogEntry(host, '\n'.join(allparas.get(host))))
                self.fireTableRowsInserted(row, row)
            self._lock.release()



    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "HOST"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._host
        return ""
