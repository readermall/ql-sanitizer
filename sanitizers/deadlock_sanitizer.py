from qiling.const import QL_INTERCEPT, QL_CALL_BLOCK, QL_VERBOSE, QL_ARCH
from qiling.os.const import *
from .sanitizer_utils import *
import threading


class DeadException(Exception):
    def __init__(self, ql: Qiling, msg: str) -> None:
        super().__init__(msg)
        self.ql = ql
        self.context = str(ql.arch.regs) if ql else "None"
        self.msg = msg

    def __str__(self):
        return f"{self.msg}: \n  [CONTEXT]: \n{self.context}"
    
class tarjan():
    def __init__(self) -> None:
        self.DFN={}
        self.LOW={}
        self.index=0
        self.graph={}
        self.stack=[]
        self.thread_index=0
        self.node_size=0


    def tarjan(self,node):
        self.index=self.index+1
        self.DFN[node]=self.index
        self.LOW[node]=self.index
        self.stack.append(node)
        
        if self.graph.get(node) != None:
            for thread_id in self.graph[node]:
                if self.DFN[thread_id]==-1:
                    self.tarjan(thread_id)
                    self.LOW[node]=min(self.LOW[node],self.LOW[thread_id])
                elif self.stack.index(node)>=0:
                    self.LOW[node]=min(self.LOW[node],self.DFN[thread_id])
        
        if self.DFN[node] == self.LOW[node]:
            ring = []
            
            top=-1
            while top != node:
                top=self.stack.pop()
                ring.append(top)
            
            if len(ring)>1:
                raise DeadException(None,"Dead Lock!")

    #检测图中是否有环
    def scan(self):
        for i,_ in self.graph.items():
            if self.DFN[i] == -1:
                self.tarjan(i)

        self.index=0
        for key,_ in self.DFN.items():
            self.DFN[key]=-1
            self.LOW[key]=-1
        

    def add(self,start_thread,end_thread):
        if self.DFN.get(start_thread) == None:
            self.DFN[start_thread]=-1
            self.LOW[start_thread]=-1

            self.thread_index=self.thread_index+1
        if self.DFN.get(end_thread) == None:
            self.DFN[end_thread]=-1
            self.LOW[end_thread]=-1

            self.thread_index=self.thread_index+1

        if self.graph.get(start_thread) == None:
            self.graph[start_thread]=[]
        
        self.graph[start_thread].append(end_thread)
        
                
    def delete(self,start_thread,end_thread):
        if self.graph[start_thread].index(end_thread)>=0:
            self.graph[start_thread].remove(end_thread)

        pass

class deadlock_sanitizer(DebugUtil):
    def __init__(self, ql:Qiling, debug_level):
        super().__init__(debug_level)
        
        self.__lock=threading.Lock()
        #self.__threadList={}                       #线程请求的锁
        self.__lockList={}                         #请求加锁的线程,第一个是持有锁的线程
                                     
        self.__ql=ql
        self.__ql.os.set_api("pthread_mutex_lock",self.__pthread_mutex_lock_enter,QL_INTERCEPT.ENTER)
        #self.__ql.os.set_api("pthread_mutex_lock",self.__pthread_mutex_lock_exit,QL_INTERCEPT.EXIT)
        #self.__ql.os.set_api("pthread_mutex_unlock",self.__pthread_mutex_unlock_enter,QL_INTERCEPT.ENTER)
        self.__ql.os.set_api("pthread_mutex_unlock",self.__pthread_mutex_unlock_exit,QL_INTERCEPT.EXIT)
        self.__tarjan=tarjan()

    def __pthread_mutex_lock_enter(self, ql:Qiling):
        try:
            # print("lock")
            # self.__lock.acquire()
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            thread_id=ql.os.thread_management.cur_thread.id
            params = ql.os.resolve_fcall_params({'mutex_ptr': int})
            lock_id = str(hex(params['mutex_ptr']))
            # if self.__threadList.get(thread_id)==None:
            #     self.__threadList[thread_id]=[]
            # self.__threadList[thread_id].append(lock_id)    
            if self.__lockList.get(lock_id) == None:
                self.__lockList[lock_id]=[]
            self.__lockList[lock_id].append(thread_id)
            
            if len(self.__lockList[lock_id])>0:    
                self.__tarjan.add(thread_id,self.__lockList.get(lock_id)[0])
                self.__tarjan.scan()
                

        except Exception as e:
            # print("unlock")
            # self.__lock.release()self.__lockList[lock_id]
            raise e
        
    def __pthread_mutex_lock_exit(self,ql:Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            thread_id=ql.os.thread_management.cur_thread.id
            # 删除
            # lock_id=self.__threadList[thread_id][0]
            # self.__lockList[lock_id].pop()
            # del self.__threadList[thread_id][0]

            pass
        finally:
            pass
            # print("unlock")
            # self.__lock.release()
       
    def __pthread_mutex_unlock_exit(self,ql:Qiling):
        try:
            self.default_debug("%s in..." % sys._getframe().f_code.co_name, debug_level=QL_DEBUG_LEVEL.DEBUG_TRACE)
            thread_id=ql.os.thread_management.cur_thread.id
            params = ql.os.resolve_fcall_params({'mutex_ptr': int})
            lock_id = str(hex(params['mutex_ptr']))

            self.__lockList[lock_id].pop()
            if len(self.__lockList[lock_id])>1:
                cur_thread=self.__lockList[lock_id][0]
            else:
                return
            # self.__threadList[thread_id].pop()

            for thread in self.__lockList[lock_id]:
                self.__tarjan.delete(thread,thread_id)
                if thread==cur_thread:
                    continue
                self.__tarjan.add(thread,cur_thread)
       
        finally:
            pass
            # self.__lock.release()
       

    def __pthread_mutex_unlock_enter(self,ql:Qiling):
        try:
            print("lock")
            self.__lock.acquire()

        except Exception as e:
            print("unlock")
            self.__lock.release()
            raise e