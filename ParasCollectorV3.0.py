#coding=utf-8
from threading import Thread
from threading import Lock
from urlparse import urlparse
import time
import java.net.URL
from burp import IBurpExtender
from burp import IProxyListener
from burp import IExtensionStateListener
import json
import os


#from burp import IHttpRequestResponse
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



class BurpExtender(IBurpExtender, IProxyListener, IExtensionStateListener):
    def registerExtenderCallbacks(self,callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('ParasCollector')
        # 记录扫描历史请求的位置，启用插件是默认为0
        self._index = 0
        self._count = 0
        self._threadLock = Lock()
        self._allParas = {}
        self._i = 0
        self._hostbalcklist = ["tracking.firefox.com.cn"] # 域名黑名单
        self._pathblacklist = ["/monitor_browser/collect/batch/",""] # 设置域名path黑名单，在该path下的将不收集，比方说心跳包，日志包，避免文件过大，脏数据问题
        callbacks.registerProxyListener(self)
        callbacks.registerExtensionStateListener(self)

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
            json.dump(self._allParas, f, ensure_ascii=False)
            print "Files will be saved at " + os.getcwd() + "/allparas.json"
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
                    self.parseJson(json.loads(body))
            parasInfo[path] = self.keyValues
            self._allParas[host] = parasInfo
        
    def extensionUnloaded(self):
        allHistory = self._callbacks.getProxyHistory()
        end = len(allHistory)
        end_t = Thread(target=self.getParas, args=(end,allHistory))
        end_t.start()

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
