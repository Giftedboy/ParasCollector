#!/usr/bin/env python
#coding=utf8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IProxyListener
#从burp中导入这几个api模块
import os
import re
import json

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
print "Files will be saved at " + os.getcwd()

def ReadFile(file):
    with open(file,"a+") as f:
        f.seek(0)
        paras = f.read().split("\n")
        return paras


def WriteToFile(file, paras):
    for para in paras:
          while '' in paras:
            paras.remove('')
    if paras == []:
        os.remove(file) # 因为之前创建了一个文件，没有参数时便删除
    else:
        paras.sort()
        with open(file,"w") as f:
            for para in paras:
                f.write(para+"\n")


class BurpExtender(IBurpExtender, IHttpListener, IHttpRequestResponse, IProxyListener):
    '''
    定义一个类，这个类继承了IBurpExtender 使其成为一个插件模块
    继承IHttpListener， 使其可以接受流经的request和response
    继承IHttpRequestResponse，使其可以获得HTTP的详细信息
    继承IProxyListener ，注册成一个代理服务器！
    '''

    def registerExtenderCallbacks(self,callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName('ParasCollector') # 设定插件名字

        callbacks.registerHttpListener(self)  # 必须得注册才具有功能
        callbacks.registerProxyListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 4 or toolFlag == 64:  # flag值代表着不同的组队，此时是 proxy 和 repeater，表示被拦截的消息
            if messageIsRequest: # 如果是一个请求
                request = messageInfo.getRequest() # 获得请求信息
                analyzedRequest = self._helpers.analyzeRequest(request) # 解析
                host = messageInfo.getHttpService().getHost() # 获取域名
                file = host+".txt"
                lines = ReadFile(file)
                paras1 = analyzedRequest.getParameters() # 获取参数，包括 json 格式的数据
                for para in paras1:
                    if para.getType() == para.PARAM_COOKIE:
                        temp = str(para.getName())
                        if temp not in lines: # 去重
                            lines.append(temp)
                    else:
                        temp = para.getName()
                        if temp not in lines:
                            lines.append(temp)
                WriteToFile(file,lines)
            if not messageIsRequest: # 如果是个响应
                host = messageInfo.getHttpService().getHost() # 获取域名
                file = host+".txt"
                lines = ReadFile(file)
                response = messageInfo.getResponse() # 获得响应信息
                analyzedResponse = self._helpers.analyzeResponse(response) # 解析
                # print analyzedResponse.getStatedMimeType()
                if analyzedResponse.getInferredMimeType() == "JSON":
                    body = response[analyzedResponse.getBodyOffset():].tostring() # 获取返回包
                    paras2 = json.loads(body).keys()
                    for para in paras2:
                        if para not in lines: # 去重
                            print str(para)
                            lines.append(str(para))
                WriteToFile(file,lines)