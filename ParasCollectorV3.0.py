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
		#i=0
		#print(self._index)
		#print(end)
		for historyReqRep in allHistory[self._index:]:
			# print("循环处理所有历史请求")
			self.analyzeReqRep(historyReqRep)
			# i = i+1
			# if i==10:
			# 	break
		# 让起始位置变为最后一个请求的位置
		self._index = end
		self._threadLock.release()
		#print(2222222222)
		#print(json.dumps(self._allParas))
		with open("allparas.json","w+") as f:
			json.dump(self._allParas, f, ensure_ascii=False)
			print "Files will be saved at " + os.getcwd() + "/allparas.json"
		
	def analyzeReqRep(self,historyReqRep):
		# 获取域名
		host = historyReqRep.getHttpService().getHost().encode('utf-8')

		# print(host)
		parasInfo = self._allParas.get(host)
		if parasInfo == None:
			parasInfo = {}
		# 处理请求
		analyzedRequest = self._helpers.analyzeRequest(historyReqRep)
		
		url = analyzedRequest.getUrl() # 获取java.net.URL对象
		path = str(url.getPath())
		if not path.endswith(".js") or not path.endswith(".png") or not path.endswith(".jpeg") or not path.endswith(".jpg") or not path.endswith(".css"):
			# print(path)
			paras1 = analyzedRequest.getParameters()
			# print(len(paras1))
			keyValues = parasInfo.get(path)

			if keyValues == None:
				keyValues = {}
			for para in paras1:
				try:
					key = str(para.getName())
					keyval = str(para.getValue())
					#print(key+"==="+keyval)

					Values = keyValues.get(key)

					if Values == None:
						Values = []
					if keyval not in Values:
						Values.append(keyval)
					keyValues[key] = Values
				except:
					continue

			# 处理响应
			
			response = historyReqRep.getResponse()
			if response != None:
				analyzedResponse = self._helpers.analyzeResponse(response)
				# print(host)
				if analyzedResponse.getInferredMimeType() == "JSON":
					body = response[analyzedResponse.getBodyOffset():].tostring() # 获取返回包
					jsonDict = json.loads(body).items() # 字典类型
					for key,keyval in jsonDict:
						#print(key)
						new_key = "Rep_" + key
						Values = keyValues.get(new_key)
						if isinstance(keyval,unicode):
							keyval = keyval.encode('utf-8')
						else:
							keyval = str(keyval)
						#print(type(keyval))
						if Values == None:
							Values = []
						if keyval not in Values:
							Values.append(keyval)

						keyValues[new_key] = Values
						#print(Values)
			parasInfo[path] = keyValues
			self._allParas[host] = parasInfo

		
	def extensionUnloaded(self):
		print(11111)
		allHistory = self._callbacks.getProxyHistory()
		self._end = len(allHistory)
		end_t = Thread(target=self.getParas, args=(self._end,allHistory))
		end_t.start()


