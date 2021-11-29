#coding=utf-8
from threading import Thread
from threading import Lock
from urlparse import urlparse
from burp import IBurpExtender
from burp import IProxyListener
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorController
from burp import ITab
import json
import os
import sys
from javax.swing import JMenuItem
from java.util import ArrayList;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing.table import AbstractTableModel;
#from burp import IHttpRequestResponse
sys.version[0] == '2':
    reload(sys)
    sys.setdefaultencoding("utf-8")# 老是会出现编码错误，所以设置一下编码
print("""
  _____                     _____      _ _           _             
 |  __ \                   / ____|    | | |         | |            
 | |__) __ _ _ __ __ _ ___| |     ___ | | | ___  ___| |_ ___  _ __ 
 |  ___/ _` | '__/ _` / __| |    / _ \| | |/ _ \/ __| __/ _ \| '__|
 | |  | (_| | | | (_| \__ | |___| (_) | | |  __| (__| || (_) | |   
 |_|   \__,_|_|  \__,_|___/\_____\___/|_|_|\___|\___|\__\___/|_|   

 ----- Contact me to improve it.A good idea is also important -----
 _________________________ QQ:2309896932 __________________________
 *************** https://www.cnblogs.com/wjrblogs/ ****************
""")

class LogEntry:
    def __init__(self, host, paras):
        self._host = host
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

class BurpExtender(IBurpExtender, IProxyListener, IExtensionStateListener,IContextMenuFactory, AbstractTableModel, IMessageEditorController, ITab):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('ParasCollector')
        # 记录扫描历史请求的位置，启用插件是默认为0
        self._log = ArrayList()
        self._index = 0
        self._count = 0
        self._threadLock = Lock()
        self._allParas = {}
        self._i = 0
        self._hostbalcklist = ["tracking.firefox.com.cn","clack.7moor.com"] # 域名黑名单
        self._pathblacklist = ["/monitor_browser/collect/batch/",""] # 设置域名path黑名单，在该path下的将不收集，比方说心跳包，日志包，避免文件过大，脏数据问题
        callbacks.registerProxyListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

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

        # 在启用插件的时候就扫描一次
        allHistory = self._callbacks.getProxyHistory()
        self._end = len(allHistory)
        start_t = Thread(target=self.getParas, args=(self._end,allHistory))
        start_t.start()
        return

    def processProxyMessage(self, messageIsRequest, messageInfo):
        # 每1000个请求扫描一次，需要注意的是，发起了1000个请求，history不一定有1000个记录
        self._count = self._count + 1
        if(self._count==1000):
            self._count=0
            # 获取到的请求是从所有请求的第一个开始的
            allHistory = self._callbacks.getProxyHistory()
            self._end = len(allHistory)
            # 采用线程的方式执行获取参数的行为，避免阻塞请求响应
            t = Thread(target=self.getParas, args=(self._end,allHistory))
            t.start()
            # t.join()
        

    def getParas(self,end,allHistory):
        # 会在线程中被改变的数需要在锁里面获取跟改变，如果以形参方式传入会导致数据错乱，不会改变的数据应当以形参传入，避免数据错乱
        self._threadLock.acquire()
        for historyReqRep in allHistory[self._index:]:
            self.analyzeReqRep(historyReqRep)
            self._i = self._i+1
        # 让起始位置变为最后一个请求的位置

        self._index = end
        
        with open("allparas.json","w+") as f:
            try:
            	json.dump(self._allParas, f, ensure_ascii=False)
            	print "Files will be saved at " + os.getcwd() + "/allparas.json"
            except BaseException,err:
            	print("file save filed,reason is:")
            	print(err)
            

        row = self._log.size()
        self._log.clear()
        for host in self._allParas.keys():
            self._log.add(LogEntry(host, json.dumps(self._allParas.get(host),sort_keys=True,indent=4,ensure_ascii=False)))
            self.fireTableRowsInserted(row, row)
        self._threadLock.release()
        
        
    def analyzeReqRep(self,historyReqRep):
        # 获取域名
        host = historyReqRep.getHttpService().getHost().encode('utf-8')
        
        parasInfo = self._allParas.get(host)
        if parasInfo == None:
            parasInfo = {}
        # 处理请求
        analyzedRequest = self._helpers.analyzeRequest(historyReqRep)
        
        url = analyzedRequest.getUrl() # 获取java.net.URL对象
        path = str(url.getPath())
        if path.endswith(".js") or path.endswith(".png") or path.endswith(".jpeg") or path.endswith(".jpg") or path.endswith(".css") or path in self._pathblacklist or host in self._hostbalcklist:
        	return
        else:
            paras1 = analyzedRequest.getParameters()
            self.keyValues = parasInfo.get(path)

            if self.keyValues == None:
                self.keyValues = {}
            for para in paras1:
                try:
                    key = str(para.getName())
                    keyval = str(para.getValue())
                    Values = self.keyValues.get(key)

                    if Values == None:
                        Values = []
                    if keyval not in Values:
                        Values.append(keyval)
                    self.keyValues[key] = Values
                except:
                    continue

            # 处理响应
            
            response = historyReqRep.getResponse()
            if response != None:
                analyzedResponse = self._helpers.analyzeResponse(response)
                if analyzedResponse.getInferredMimeType() == "JSON":
                    body = response[analyzedResponse.getBodyOffset():].tostring() # 获取返回包
                    try:
                    	self.parseJson(json.loads(body))
                    except:
                    	print("Not a json")
            parasInfo[path] = self.keyValues
            self._allParas[host] = parasInfo
        
    def extensionUnloaded(self):
        allHistory = self._callbacks.getProxyHistory()
        end = len(allHistory)
        end_t = Thread(target=self.getParas, args=(end,allHistory))
        end_t.start()

    def createMenuItems(self, invocation):
        if invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER or IBurpExtenderCallbacks.TOOL_PROXY:
            menu = []
            menu.append(JMenuItem("getParas", None, actionPerformed=lambda x, y=invocation: self.printParas(x, y)))

        return menu

    def printParas(self,event,invocation):
        reqreps = invocation.getSelectedMessages()
        for reqrep in reqreps:
            analyzedRequest = self._helpers.analyzeRequest(reqrep)

            url = analyzedRequest.getUrl()
            host = str(url.getHost())
            path = str(url.getPath())
            print(host+path+"\n")
            hostparas = self._allParas.get(host)
            if hostparas != None:
                pathparas = hostparas.get(path)
                if pathparas != None:
                    try:
                        print(json.dumps(pathparas,sort_keys=True,indent=4,ensure_ascii=False))
                    except BaseException,err:
                        print(err)
                else:
                    print("path_noParas1")
            else:
                print("host_noParas2")

    def parseJson(self,json):
        keyvals = json.items()
        length = len(keyvals)
        index = 0
        for key,val in keyvals:
            index = index + 1
            if isinstance(val,dict):
                Values = self.keyValues.get(key)
                if Values == None:
                    Values = []
                if "" not in Values:
                	Values.append("")
                self.keyValues[key] = Values
                self.parseJson(val)
            elif isinstance(val,list):
                for listval in val:
                    if isinstance(listval,dict):
                        self.parseJson(listval)
                    else:
                        Values = self.keyValues.get(key)
                        if Values == None:
                            Values = []
                        if isinstance(listval,unicode):
                            listval = listval.encode('utf-8')
                        else:
                            listval = str(listval)
                        Values.append(listval)
                        self.keyValues[key] = Values
            else:
                Values = self.keyValues.get(key)
                if Values == None:
                    Values = []
                if isinstance(val,unicode):
                    val = val.encode('utf-8')
                else:
                    val = str(val)
                if val not in Values:
                    Values.append(val)
                self.keyValues[key] = Values
                if length==index:
                    return

    def getTabCaption(self):
        return "ParasCollector"
    
    def getUiComponent(self):
        return self._splitpane

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
