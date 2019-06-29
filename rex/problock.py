import angr

import copy


class ARGTYPE:
	Voffset = 1,
	Vaddr = 2,
	Vconst = 3,
	Vtmp = 4,
	Vstackv = 5,
	Vunkown = 6

class FARGTYPE:
	Vstring = 1,
	Vint = 2,
	Vlen = 3,
	Vnone = 4

class funcop:
	def __init__(self):
		self.functionname = "";
		self.src = 0;
		self.len = 0;
		self.dest = 0;
		self.srctype = 0;
		self.desttype = 0,
		self.returntype = "";
	
	def setfunctionname(self,funcname):
		self.functionname = funcname;

	def getfunctionname(self):
		return self.functionname;

	def setfuncsrc(self,funcsrc):
		self.src = funcsrc;

	def getfuncsrc(self):
		return self.src;

	def setfunclen(self,funclen):
		self.len = funclen;

	def getfunclen(self):
		return self.funclen;

	def setfuncdest(self,funcdest):
		self.dest = funcdest;

	def getfuncdest(self):
		return self.dest;

	def getreturntype(self):
		return self.returntype;
	
	def setreturntype(self,funcreturntype):
		self.returntype = funcreturntype;

	def setsrctype(self,srctype):
		self.srctype = srctype;

	def setdesttype(self,desttype):
		self.desttype = desttype;

	def getsrctype(self):
		return self.srctype;

	def getdesttype(self):
		return self.desttype;

	def listpp(self):
		msg = "";
		msg += "functionname:%s "%self.functionname;
		msg += " src:%d "%self.src;
		if self.srctype == FARGTYPE.Vstring:
			msg += " string ";
		elif self.srctype == FARGTYPE.Vint:
			msg += " int ";
		msg += " dest:%d "%self.dest;
		if self.desttype == FARGTYPE.Vstring:
			msg += " string ";
		elif self.desttype == FARGTYPE.Vint:
			msg += " int ";
		msg += " len:%d "%self.len;
		print(msg);

class function:
	def __init__(self):
		self.functionname = "";
		self.addr = list();
		self.arg = list();
		self.farg = list();
		self.aargloffset = list();
		self.rule=list();
		self.ruledes=list();
		self.limitl=list();
		self.functiontype = "";
		self.returntype = "";

	def addlimit(self,limit):
		self.limitl.append(limit);

	def getlimitindex(self,index):
		return self.limitl[index];

	def getrule(self):
		return self.rule;

	def setrule(self,rule):
		self.rule = rule;

	def addruledes(self,ruledesitem):
		self.ruledes.append(ruledesitem);

	def addrule(self,rulel):
		self.rule.append(rulel);

	def getruleindex(self,index):
		return self.rule[index];
	
	def getruledesindex(self,index):
		return self.ruledes[index];

	def getfunctionname(self):
		return self.functionname;

	def setfunctionname(self,functionname):
		self.functionname = functionname;

	def getfunctiontype(self):
		return self.functiontype;

	def setfunctiontype(self,functiontype):
		self.functiontype = functiontype;

	def getarg(self):
		return self.arg;

	def addarg(self,arg):
		self.arg.append(arg);

	def fillarg(self,argitem,index):
		while len(self.arg) <= index:
			self.arg.append("");
		self.arg[index] = argitem;
	
	def addfarg(self,arg):
		self.farg.append(arg);

	def getfarg(self):
		return self.farg;
	
	def farglen(self):
		return len(self.farg);

	def getfargitem(self,index):
		return self.farg[index];
	
	def setreturntype(self,returntype):
		self.returntype = returntype;
	
	def getreturntype(self):
		return self.returntype;

	def getfunctionaddr(self):
		return self.addr;

	def addfunctionaddr(self,addr):
		if not addr in self.addr:
			self.addr.append(addr);

	def clearfunctionaarg(self):
		self.aargloffset = list();

	def addfunctionaarg(self,offset):
		self.aargloffset.append(offset);

	def getfunctionaarg(self,locat):
		if len(self.aargloffset) <= locat:
			return None;
		return self.aargloffset[locat];

	def setfunctionaargoffset(self,locat,v):
		if len(self.aargloffset) <= locat:
			return False;
		self.aargloffset[locat] = v;
		return True;
	
	def getfunctionaarglist(self):
		return self.aargloffset;

	def listallfagrpp(self):
		print(self.functionname);
		'''for i in range(0,len(self.addr)):
			msg = "";
			msg += "addr:0x%X "%self.addr[i];
			print(msg);'''
		for fargitemindex in range(0,len(self.farg)):
			msg = "";
			fargitem = self.farg[fargitemindex];
			faddrv = fargitem[0];
			faddrtype = fargitem[1];
			msg += " faddr:%d"%faddrv;
			msg += " faddrtype:%d"%faddrtype;
			msg += " limit:%s"%self.limitl[fargitemindex];
			msg += " rule:%d"%self.rule[fargitemindex];
			msg += " ruledes:%s"%self.ruledes[fargitemindex];
			#msg += ""
			print(msg);

class FUNCTIONTYPE:
	inner = 1,
	extern = 2


class CHILDRENSIZE:
	Vexit = 1,
	Vnext = 2,
	Vlr = 3

class CHILRENSLIDE:
	Vleft = 1,
	Vright = 2

class traceinfo:
	def __init__(self):
		self.functionname = ""
		self.vl = list();
		self.vtypel = list();
		self.metal = list();
		self.needtrace = list();
		self.argtypel = list();
		self.fresultl = list();
		self.faddrl = list();
		self.rulel = list();
		self.ruledesl = list();
		self.calleaddr = list();
		self.nop = list();
		self.frulel = list();
		self.map = dict();
	
	def addalllist(self,v,vtype,meta,argtype,calleaddr,rule,ruledes,fr=""):
		index = len(self.vl);
		self.vl.append(v);
		self.vtypel.append(vtype);
		if argtype == FARGTYPE.Vnone:
			self.needtrace.append(False);
		else:
			self.needtrace.append(True);
		self.nop.append(True);
		self.metal.append(meta);
		self.argtypel.append(argtype);
		self.fresultl.append("");
		self.faddrl.append(0x0);
		self.calleaddr.append(calleaddr);
		self.rulel.append(rule);
		self.ruledesl.append(ruledes);
		self.frulel.append(fr);
		self.map[str(v) +" " + str(vtype)] = index;
	
	def getallitem(self,index):
		if index < 0 or index >= self.alllen():
			return None;
		return self.vl[index],self.vtypel[index],self.metal[index],self.needtrace[index],self.argtypel[index],self.fresultl[index],self.faddrl[index],self.rulel[index],self.ruledesl[index],self.calleaddr[index],self.nop[index],self.frulel[index]

	def keyin(self,v,vtype):
		if str(v) + " " + str(vtype) in self.map:
			return True;
		return False;
	
	def keyupdate(self,v,vtype,nv,nvtype):
		if not self.keyin(v,vtype):
			return False;
		index = self.map[str(v) + " " + str(vtype)];
		del self.map[str(v) +" " + str(vtype)];
		self.map[str(nv) + " " + str(nvtype)] = index;
		self.vl[index] = nv;
		self.vtypel[index] = nvtype;
		return True;
	
	def keyadddup(self,v,vtype,nv,nvtype):
		if not self.keyin(v,vtype):
			return False;
		index = self.map[str(v) + " " + str(vtype)];
		self.map[str(nv) + " " + str(nvtype)] = index;
		return True;

	def setfunctionname(self,fn):
		self.functionname = fn;

	def getfunctionname(self):
		return self.functionname;

	def alllen(self):
		return len(self.vl);

	def getindexvl(self,index):
		return self.vl[index];

	def getindexvtypel(self,index):
		return self.vtypel[index];
	
	def setntrace(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.needtrace[index] = False;

	def gettrace(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		return self.needtrace[index];

	def setfresult(self,v,vtype,result):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.fresultl[index] = result;

	def setnprint(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.nop[index] = False;
		

	def getfresult(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		#print(index);
		return self.fresultl[index];

	def setfaddr(self,v,vtype,fa):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.faddrl[index] = fa;

	def getfaddr(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		return self.faddrl[index];

	def setmeta(self,v,vtype,meta):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.metal[index] = meta;

	def getmeta(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		return self.metal[index];

	def setargtype(self,v,vtype,argtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.argtypel[index] = argtype;

	def getargtype(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		return self.argtypel[index];
	
	def getcalleaddr(self,v,vtype):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		return self.calleaddr[index];

	def setcalleaddr(self,v,vtype,addr):
		if not self.keyin(v,vtype):
			return None;
		index = self.map[str(v) + " " + str(vtype)];
		self.argtypel[index] = addr;
	
	def settntrace(self):
		for i in range(0,len(self.vl)):
			if not self.vtypel[i] == ARGTYPE.Voffset and not self.vtypel[i]==ARGTYPE.Vstackv:
				self.needtrace[i] = False;
				self.nop[i] = False;

	def listallpp(self,dt):
		msg = "";
		for i in range(0,len(self.vl)):	
			if not self.nop[i] or self.needtrace[i]:
				continue;
			self.nop[i] = False;
			if self.argtypel[i] == FARGTYPE.Vstring and not isinstance(self.fresultl[i],str):
				continue;
			elif self.argtypel[i] == FARGTYPE.Vint and not isinstance(self.fresultl[i],int):
				continue;
			if self.argtypel[i] == FARGTYPE.Vstring and (len(self.fresultl[i]) == 0 or self.fresultl[i] == "" or self.fresultl[i] == None):
				continue;
			elif self.argtypel[i] == FARGTYPE.Vint and not len(self.frulel[i]) == 0 and isinstance(self.fresultl[i],int):
				limit = 0;
				if self.frulel[i][0] == "<":
					limit = int(self.frulel[i][1:]);
					if self.fresultl[i] >= limit:
						continue;
				elif self.frulel[i][0] == "=":
					limit = int(self.frulel[i][1:]);
					if not self.fresultl[i] == limit:
						continue;
				elif self.frulel[i][0] == ">":
					limit = int(self.frulel[i][1:]);
					if self.fresultl[i] <= limit:
						continue;
			msg += "v:%d "%self.vl[i];
			msg += "functionname:%s "%self.functionname;
			msg += "meta:%s "%self.metal[i];
			msg += "vtype:%d "%self.vtypel[i];
			msg += "argtype:%d "%self.argtypel[i];
			msg += "calleaddr:0x%X "%self.calleaddr[i];
			msg += "faddr:0x%X "%self.faddrl[i];
			msg += "fresult:%s "%self.fresultl[i];
			msg += "rule:%s "%self.rulel[i];
			msg += "ruledes:%s "%self.ruledesl[i];
			'''if self.needtrace[i]:
				msg += "needtrace ";
			else:
				msg += "noneedtrace "'''
			#msg += "index:%d "%self.map[str(self.vl[i]) + " " + str(self.vtypel[i])]
			print("listallpp");
			print(msg);
			dt[str(self.functionname)+str(self.faddrl[i])+str(self.metal[i])+str(self.calleaddr[i])+str(self.fresultl[i])] = (msg,self.rulel[i],self.ruledesl[i]);
			#print(len(self.fresultl[i]));
			msg = "";

	def listdebugpp(self):
		msg = "";
		for i in range(0,len(self.vl)):	
			'''if not self.nop[i] or self.needtrace[i]:
				continue;
			self.nop[i] = False;
			if self.argtypel[i] == FARGTYPE.Vstring and (len(self.fresultl[i]) == 0 or self.fresultl[i] == "" or self.fresultl[i] == None):
				continue;
			elif self.argtypel[i] == FARGTYPE.Vint and not len(self.frulel[i]) == 0 and isinstance(self.fresultl[i],int):
				limit = 0;
				if self.frulel[i][0] == "<":
					limit = int(self.frulel[i][1:]);
					if self.fresultl[i] >= limit:
						continue;
				elif self.frulel[i][0] == "=":
					limit = int(self.frulel[i][1:]);
					if not self.fresultl[i] == limit:
						continue;
				elif self.frulel[i][0] == ">":
					limit = int(self.frulel[i][1:]);
					if self.fresultl[i] <= limit:
						continue;'''
			msg += "v:%d "%self.vl[i];
			msg += "functionname:%s "%self.functionname;
			msg += "meta:%s "%self.metal[i];
			msg += "vtype:%d "%self.vtypel[i];
			msg += "argtype:%d "%self.argtypel[i];
			msg += "calleaddr:0x%X "%self.calleaddr[i];
			msg += "faddr:0x%X "%self.faddrl[i];
			msg += "fresult:%s "%self.fresultl[i];
			msg += "rule:%s "%self.rulel[i];
			msg += "ruledes:%s "%self.ruledesl[i];
			if self.needtrace[i]:
				msg += "needtrace ";
			else:
				msg += "noneedtrace "
			#msg += "index:%d "%self.map[str(self.vl[i]) + " " + str(self.vtypel[i])]
			print(msg);
			#dt[str(self.functionname)+str(self.faddrl[i])+str(self.metal[i])+str(self.calleaddr[i])+str(self.fresultl[i])] = (msg,self.rulel[i],self.ruledesl[i]);
			#print(len(self.fresultl[i]));
			msg = "";

	def ntlen(self):
		result = 0;
		for nitem in self.needtrace:
			if nitem:
				result += 1;
		return result;

	def ntlen(self):
		result = 0;
		for nitem in self.needtrace:
			if nitem:
				result += 1;
		return result;


def traceinfocopy(tis):
	tit = traceinfo();
	tit.vl = copy.copy(tis.vl);
	tit.vtypel = copy.copy(tis.vtypel);
	tit.metal = copy.copy(tis.metal);
	tit.needtrace = copy.copy(tis.needtrace);
	tit.argtypel = copy.copy(tis.argtypel);
	tit.fresultl = copy.copy(tis.fresultl);
	tit.faddrl = copy.copy(tis.faddrl);
	tit.nop = copy.copy(tis.nop);
	tit.map = copy.copy(tis.map);
	#tit.vlenl = copy.copy(tis.vlenl);
	tit.calleaddr = copy.copy(tis.calleaddr);
	tit.rulel = copy.copy(tis.rulel);
	tit.ruledesl = copy.copy(tis.ruledesl);
	tit.frulel = copy.copy(tis.frulel);
	tit.functionname = tis.functionname;
	return tit;

def finishfuncdetail(function,pnode):
        function.clearfunctionaarg();
        if len(function.getarg()) <= 4:
                comlist = pnode.getcomarglist();
                for i in range(0,len(function.getarg())):
                        function.addfunctionaarg([comlist[i],ARGTYPE.Voffset]);
        else:
                aargnum = len(function.getarg());
                comlist = pnode.getcomarglist();
                for i in range(0,4):
                        function.addfunctionaarg([comlist[i],ARGTYPE.Voffset]);
                for i in range(4,aargnum):
                        function.addfunctionaarg([i-4,ARGTYPE.Vstackv]);

def func2traceinfo(function,beginaddr):
	ti = traceinfo();
        functionname = function.getfunctionname();
	ti.setfunctionname(functionname);
        functionargl = function.getfunctionaarglist();
        indexi = 0;
        for fargitemindex in range(0,function.farglen()):
		fargitem = function.getfargitem(fargitemindex);
                index = fargitem[0] - 1;
		v = -1;
		vtype = ARGTYPE.Vunkown;
                if index < len(functionargl) and index >= 0:
                	v = functionargl[index][0];
                	vtype = functionargl[index][1];
                vmeta = " arg (" + function.getarg()[index] + ")";
                vargtype = fargitem[1];
                rule = function.getruleindex(indexi);
		ruledes = function.getruledesindex(indexi);
                limit = function.getlimitindex(indexi);
                ti.addalllist(v,vtype,vmeta,vargtype,beginaddr,rule,ruledes,limit);
                indexi += 1;
	return ti;

def traceinfo2func(ti,node,functionname):
	fn = function();
	fn.setfunctionname(functionname);
	for i in range(0,ti.alllen()):
		v,vtype,metal,needtrace,argtype,fresult,faddr,rule,ruledes,calleaddr,nop,limit = ti.getallitem(i);
		if not needtrace:
			continue;
		argnumleast = 0;
		if vtype == ARGTYPE.Voffset and v in node.comarglist:
			argindex = node.comarglist.index(v) + 1;
			fn.addfarg([argindex,argtype]);
			argnumleast = argindex - 1;
		elif vtype == ARGTYPE.Vstackv:
			pass;
		if argtype == FARGTYPE.Vstring:
			fn.fillarg("string",argnumleast);
		elif argtype == FARGTYPE.Vint:
			fn.fillarg("int",argnumleast);
		fn.setreturntype("");
		fn.addrule(rule);
		fn.addruledes(ruledes);
		fn.addlimit(limit);
	finishfuncdetail(fn,node);
	return fn;
	
class functioncontainer:
	def __init__(self):
		self.functions = list();
		self.functionsdic = dict();

	def addfunction(self,function):
		if function.getfunctionname() in self.functionsdic or any(s in function.getfunctionaddr() for s in self.functionsdic.keys()):
			return;
		index = len(self.functions);
		self.functions.append(function);
		self.functionsdic[function.getfunctionname()] = index;
		for addr in function.getfunctionaddr():
			self.functionsdic[str(addr)] = index;
		
	def getfunction(self,info):
		if not info in self.functionsdic:
			return None;
		index = self.functionsdic[info];
		return self.functions[index];

	def addfunctionaddr(self,name,addr):
		if not name in self.functionsdic or addr in self.functionsdic:
			return;
		index = self.functionsdic[name];
		self.functionsdic[str(addr)] = index;

'''def functioncall( filename,blockbegin, instructions):
        #print(dir(obj))
        obj = subprocess.Popen(["/usr/bin/r2", filename],stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE);
        obj.stdin.write('s ' + blockbegin + '\n');
        obj.stdin.write('pds > /dev/null\n');
        #obj.stdout.read();
        #print('pd ' + instructions + '> /tmp/' + rs +'\n');
        obj.stdin.write('pd ' + instructions + '\n');
        obj.stdin.write('exit\n');
        print(filename);
        print(blockbegin);
        print(instructions);
        #obj.stdin.flush();
        obj.wait();
        
        cmd_out = "";
        cmd_out = obj.stdout.read();
        #print("begin");
        #while line:
        #       cmd_out = line + "\n";
        #       line = obj.stdout.readline();
        #print("output");
        #print(cmd_out);
        #return ;
        #print("end");
        buf = StringIO.StringIO(cmd_out);
        #buf = open("/tmp/"+rs,'r');
        line = buf.readline();
        tmpbuf = "";
        while line:
                #print(line);
                if not line.find("sym") == -1:
                        tmpbuf = line;
                line = buf.readline();
        if tmpbuf == "":
                return;
        else:
                tmpbuf = tmpbuf[tmpbuf.rindex("sym")+len("sym") +1:len(tmpbuf)];
                if not tmpbuf.find(";") == -1:
                        tmpbuf = tmpbuf[0:tmpbuf.index(";")].strip();
                last = 0;
                for x in tmpbuf:
                        if x not in string.printable:
                                break;
                        last += 1;
                tmpbuf = tmpbuf[0:last];
                print(tmpbuf);'''

class problock:
	def __init__(self,irsb=None,lcom = None):
		self.stack = list();
		self.stackoffset = 0;
		self.bpoffset = None;
		self.bp_offset = 0;
		self.leftchildren = list();
		self.rightchildren = list();
		self.parents = list();
		self.arch = "";
		self.sp = 0;
		self.beginaddr = 0;
		self.size = 0;
		self.iscallextern = False;
		self.externfunctioncall = "";
		self.externfunctionarg = list();
		self.externreturnvalue = 0;
		self.externactarg = list();
		self.comarglist = list();
		self.argunfixed = list();
		self.returnoffset = 0;
		self.lcom = lcom;
		self.irsb = irsb;
		self.rootpath = list();
		self.maxp = 0;
		self.minn = 0;
		self.transonce = False;
		self.sprelate = dict();
		self.wordlen = 0;
		self.stackfixnum = 0x0;
		self.bp = 0x0;
		self.stackregoffset = dict();
		self.soff = 0;
		self.bl = 0;
		if not irsb == None:
			self.arch = self.irsb.arch;
			self.sp = self.irsb.arch.sp_offset;
			self.bp = self.irsb.arch.bp_offset;
			self.beginaddr = self.irsb.addr;
			self.size = self.irsb.size;
			self.iscallextern = False;
			self.externfunctioncall = "";
			self.externfunctionarg = list();
			self.externreturnvalue = 0;
			self.externactarg = list();
			if self.irsb.arch.vex_arch == "VexArchARM":
				self.comarglist.append(self.irsb.arch.get_register_offset("r0"));
				self.comarglist.append(self.irsb.arch.get_register_offset("r1"));
				self.comarglist.append(self.irsb.arch.get_register_offset("r2"));
				self.comarglist.append(self.irsb.arch.get_register_offset("r3"));
				self.returnoffset = self.irsb.arch.get_register_offset("r0");
				self.argunfixed.append(self.irsb.arch.get_register_offset("r0"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("r1"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("r2"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("r3"));
			elif self.irsb.arch.vex_arch == "VexArchMIPS32":
				self.comarglist.append(self.irsb.arch.get_register_offset("a0"));
				self.comarglist.append(self.irsb.arch.get_register_offset("a1"));
				self.comarglist.append(self.irsb.arch.get_register_offset("a2"));
				self.comarglist.append(self.irsb.arch.get_register_offset("a3"));
				self.returnoffset = self.irsb.arch.get_register_offset("v0");
				self.argunfixed.append(self.irsb.arch.get_register_offset("v0"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("v1"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("a0"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("a1"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("a2"));
				self.argunfixed.append(self.irsb.arch.get_register_offset("a3"));
			elif self.irsb.arch.vex_arch == "VexArchMIPSel":
				self.comarglist.append(self.irsb.arch.get_register_offset("r0"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r1"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r2"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r3"));
                                self.returnoffset = self.irsb.arch.get_register_offset("r0");
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r0"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r1"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r2"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r3"));
			elif self.irsb.arch.vex_arch == "VexArchMIPS64":
				self.comarglist.append(self.irsb.arch.get_register_offset("r0"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r1"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r2"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r3"));
                                self.returnoffset = self.irsb.arch.get_register_offset("r0");
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r0"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r1"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r2"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r3"));
			elif self.irsb.arch.vex_arch == "VexArchIntel":
				self.comarglist.append(self.irsb.arch.get_register_offset("r0"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r1"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r2"));
                                self.comarglist.append(self.irsb.arch.get_register_offset("r3"));
                                self.returnoffset = self.irsb.arch.get_register_offset("r0");
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r0"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r1"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r2"));
                                self.argunfixed.append(self.irsb.arch.get_register_offset("r3"));
			self.maxp = 2 ** (self.arch.bits - 1) - 1;
			self.minn = -2 ** (self.arch.bits - 1);
			self.wordlen = self.irsb.arch.bits / 8;
	
	def instack(self,v,vtype):
		if str(v) + " " + str(vtype) in self.sprelate:
			return True;
		else:
			return False;

	def getstackdata(self,v,vtype):
		if not self.instack(v,vtype):
			return [0,ARGTYPE.Vunkown];
		else:
			return self.stack[self.sprelate[str(v) + " " + str(vtype)]/ self.bl + self.soff];
	
	def unfixedarglen(self):
		return len(self.argunfixed);

	def getunfixedarg(self,index):
		return self.argunfixed[index];

	def getwordlen(self):
		return self.wordlen;

	def setbeginaddr(self,begin):
		self.beginaddr=begin;

	def getbeginaddr(self):
		return self.beginaddr;

	def getcomarglist(self):
		return self.comarglist;

	def getirsb(self):
		return self.irsb;

	def tracearg(self,arginfo):
		arglist = list();
		argtypelist = list();
		for aitem in arginfo:
			arg = arginfo[0];
			argtype = arginfo[1];
		

	def addleftchildren(self,problocknode):
		self.leftchildren.append(problocknode);
		return CHILRENSLIDE.Vleft,len(self.leftchildren) - 1;

	def addrightchildren(self,problocknode):
		self.rightchildren.append(problocknode);
		return CHILRENSLIDE.Vright,len(self.rightchildren) - 1;

	def addparents(self,problocknode):
		self.parents.append(problocknode);

	def getleftchildren(self):
		return self.leftchildren;
	
	def addrootpath(self,path):
		self.rootpath.append(path);

	def getrootpath(self):
		return self.rootpath;

	def getrightchildren(self):
		return self.rightchildren;

	def getparents(self):
		return self.parents;

	def blockstack(self):
		pass;
		
	def exitstate(self):
		pass;
	
	def blockqemuex(self):
		pass;

	def addexternflag(self):
		self.iscallextern = True;

	def externflag(self):
		return self.iscallextern;
	
	def addexternfun(self,name):
		self.externfunctioncall = name;

	def getexternfun(self):
		return self.externfunctioncall;

	def addexternfunarg(self,arg):
		self.externfunctionarg.append(arg);

	def constrans(self,num):
		result = 0;
		if num < self.maxp:
			result = num;
		else:
			result = (num - self.maxp) + self.minn - 1;
		return result;
	def getbpspoffset(self):
		if self.bpoffset == None or self.stackoffset == None:
			return None;
		return self.bpoffset - self.stackoffset;

	def getnextblockaddr(self,spbpoffset=None):
		result = list();
		pastaddress = list();
		nowaddress = list();
		tmpresult = list();
		now = None;
		past = None;
		lrnowaddr=None;
		lrpastaddr=None;
		lrex=None;
		if self.irsb == None:
			return result;
		vmin = 0;
		vmax = 0;
		voff = 0;
		self.sprelate[str(self.sp) + " " + str(ARGTYPE.Voffset)] = 0;
		bytelen = self.irsb.arch.bits / 8;
		if not spbpoffset == None:
			if spbpoffset > vmax:
				while vmax < spbpoffset:
					self.stack.append(["",ARGTYPE.Vunkown]);
					vmax += 1;
			elif spbpoffset < vmin:
				voff = - spbpoffset;
				while spbpoffset  < vmin:
					self.stack.insert(0,["",ARGTYPE.Vunkown]);
					vmin -= 1;
			self.sprelate[str(self.bp) + " " + str(ARGTYPE.Voffset)] = spbpoffset * self.getwordlen();
			
		self.stack.append(["",ARGTYPE.Vunkown]);
		for sitem in self.irsb.statements:
			if sitem.tag == "Ist_IMark":
				past = now;
				now = sitem.addr;
			elif sitem.tag == "Ist_Exit":
				tmpresult.append([sitem,CHILDRENSIZE.Vexit]);
				nowaddress.append(now);
				pastaddress.append(past);
			elif sitem.tag == "Ist_Put":
				if sitem.offset == self.arch.lr_offset and self.irsb.jumpkind == "Ijk_Call":
					for ex in sitem.expressions:
						if ex.tag == "Iex_Const":
							lrnowaddr=now;
							lrpastaddr=past;
							lrex=ex;
				for ex in sitem.expressions:
					if ex.tag == "Iex_RdTmp":
						if str(ex.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate:
							self.stackregoffset[sitem.offset] = self.sprelate[str(ex.tmp) + " " + str(ARGTYPE.Vtmp)];
						if not str(ex.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate and sitem.offset in self.stackregoffset:
							del self.stackregoffset[sitem.offset];
			# for stack
			if self.transonce:
				continue;
			stackvtmp = 0;
                        if sitem.tag == "Ist_WrTmp":
                      		eitem = sitem.data;
                                if eitem.tag == "Iex_Unop":
                                	pass;
                               	elif eitem.tag == "Iex_RdTmp":
                                	pass;
                               	elif eitem.tag == "Iex_Load":
                                	pass;
                               	elif eitem.tag == "Iex_Const":
                                	pass;
                                elif eitem.tag == "Iex_Binop":
                                	if eitem.op == "Iop_Add32":
                                        	arg1 = eitem.args[0];
                                                arg2 = eitem.args[1];
                                        	if arg1.tag == "Iex_RdTmp" and str(arg1.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate and arg2.tag == "Iex_Const":
							stackvtmp = self.sprelate[str(arg1.tmp) + " " + str(ARGTYPE.Vtmp)] + self.constrans(arg2.constants[0].value);
							if stackvtmp / bytelen > vmax:
								while vmax < stackvtmp / bytelen:
									self.stack.append(["",ARGTYPE.Vunkown]);
									vmax += 1;
							elif stackvtmp / bytelen < vmin:
								voff = - stackvtmp / bytelen;
								while stackvtmp / bytelen < vmin:
									self.stack.insert(0,["",ARGTYPE.Vunkown]);
									vmin -= 1;
                                                        self.sprelate[str(sitem.tmp) + " " + str(ARGTYPE.Vtmp)] = stackvtmp;
                                           	elif arg2.tag == "Iex_RdTmp" and str(arg2.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate and arg1.tag == "Iex_Const":
							stackvtmp = self.sprelate[str(arg2.tmp) + " " + str(ARGTYPE.Vtmp)] + self.constrans(arg1.constants[0].value);
							if stackvtmp / bytelen > vmax:
								while vmax < stackvtmp / bytelen:
									self.stack.append(["",ARGTYPE.Vunkown]);
									vmax += 1;
							elif stackvtmp / bytelen < vmin:
								voff = - stackvtmp / bytelen;
								while stackvtmp / bytelen < vmin:
									self.stack.insert(0,["",ARGTYPE.Vunkown]);
									vmin -= 1;
                                                       	self.sprelate[str(sitem.tmp) + " " + str(ARGTYPE.Vtmp)] = stackvtmp;
                              		elif eitem.op == "Iop_Sub32":
                                        	arg1 = eitem.args[0];
                                              	arg2 = eitem.args[1];
                                                if arg1.tag == "Iex_RdTmp" and str(arg1.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate and arg2.tag == "Iex_Const":
							stackvtmp = self.sprelate[str(arg1.tmp) + " " + str(ARGTYPE.Vtmp)] - self.constrans(arg2.constants[0].value);
							if stackvtmp / bytelen > vmax:
								while vmax < stackvtmp / bytelen:
									self.stack.append(["",ARGTYPE.Vunkown]);
									vmax += 1;
							elif stackvtmp / bytelen < vmin:
								voff = - stackvtmp / bytelen;
								while stackvtmp / bytelen < vmin:
									self.stack.insert(0,["",ARGTYPE.Vunkown]);
									vmin -= 1;
                                                        self.sprelate[str(sitem.tmp) + " " + str(ARGTYPE.Vtmp)] = stackvtmp;
                                           	elif arg2.tag == "Iex_RdTmp" and str(arg2.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate and arg1.tag == "Iex_Const":
							stackvtmp = self.sprelate[str(arg2.tmp) + " " + str(ARGTYPE.Vtmp)] - self.constrans(arg1.constants[0].value);
							if stackvtmp / bytelen > vmax:
								while vmax < stackvtmp / bytelen:
									self.stack.append(["",ARGTYPE.Vunkown]);
									vmax += 1;
							elif stackvtmp / bytelen < vmin:
								voff = - stackvtmp / bytelen;
								while stackvtmp / bytelen < vmin:
									self.stack.insert(0,["",ARGTYPE.Vunkown]);
									vmin -= 1;
                                                	self.sprelate[str(sitem.tmp) + " " + str(ARGTYPE.Vtmp)] = stackvtmp;
                  		elif eitem.tag == "Iex_Get":
                                	 if str(eitem.offset) + " " + str(ARGTYPE.Voffset) in self.sprelate:
						stackvtmp = self.sprelate[str(eitem.offset) + " " + str(ARGTYPE.Voffset)];
						if stackvtmp / bytelen > vmax:
							while vmax < stackvtmp / bytelen:
								self.stack.append(["",ARGTYPE.Vunkown]);
								vmax += 1;
						elif stackvtmp / bytelen < vmin:
							voff = - stackvtmp / bytelen;
							while stackvtmp / bytelen  < vmin:
								self.stack.insert(0,["",ARGTYPE.Vunkown]);
								vmin -= 1;
                                        	self.sprelate[str(sitem.tmp) + " " + str(ARGTYPE.Vtmp)] = stackvtmp;
                        elif sitem.tag == "Ist_Store":
				destt = sitem.addr;
				srct = sitem.data;
                                if destt.tag == "Iex_RdTmp" and srct.tag == "Iex_RdTmp":
                                        if str(destt.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate:
                                                self.stack[self.sprelate[str(destt.tmp) + " " + str(ARGTYPE.Vtmp)] / bytelen + voff] = [srct.tmp,ARGTYPE.Vtmp];
                                elif destt.tag == "Iex_RdTmp" and srct.tag == "Iex_Const":
                                        if str(destt.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate:
                                                self.stack[self.sprelate[str(destt.tmp) + " " + str(ARGTYPE.Vtmp)] / bytelen + voff] = [srct.constants[0].value,ARGTYPE.Vconst];
			elif sitem.tag == "Ist_Put":
				if sitem.offset == self.arch.sp_offset and sitem.data.tag == "Iex_RdTmp" and str(sitem.data.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate:
					self.stackoffset = self.sprelate[str(sitem.data.tmp) + " " + str(ARGTYPE.Vtmp)] / bytelen;
				if sitem.offset == self.arch.bp_offset and sitem.data.tag == "Iex_RdTmp" and str(sitem.data.tmp) + " " + str(ARGTYPE.Vtmp) in self.sprelate:
					self.bpoffset = self.sprelate[str(sitem.data.tmp) + " " + str(ARGTYPE.Vtmp)]/bytelen;
		self.soff = voff;
		self.bl = bytelen;
		self.stackfixnum = -vmin;
		self.transonce = True;
		nowaddress.append(now);
		pastaddress.append(past);
		tmpresult.append([self.irsb.next,CHILDRENSIZE.Vnext]);
		#if self.beginaddr == 0x1056c or self.beginaddr == 0x10550:
		#	print("stack:0x%X"%self.beginaddr);
		#	print(self.stack);
		#	print(self.sprelate);
		#	print(self.bpoffset);
		#	print(self.stackoffset);
		if not lrex == None:
			nowaddress.append(lrnowaddr);
			pastaddress.append(lrpastaddr);
			tmpresult.append([lrex,CHILDRENSIZE.Vlr]);

		for i in range(0,len(tmpresult)):
			sitem = tmpresult[i][0];
			slide = tmpresult[i][1];
			if sitem.tag == "Ist_Exit":
				if sitem.dst.tag == "Ico_U32":
					result.append([str(sitem.dst.value),slide]);
			elif sitem.tag == "Iex_Const":
				for tmpcon in sitem.constants:
					result.append([str(tmpcon.value),slide]);
			elif sitem.tag == "Iex_RdTmp":
				nowaddr = nowaddress[i];
				pastaddr = pastaddress[i];
				nextaddr = self.translatetmp2function(nowaddr,pastaddr);
				if nextaddr == None:
					pass;
				else:
					result.append([nextaddr,slide]);
		return result;


	def translatetmp2function(self,nowaddr,pastaddr):
		if nowaddr in self.lcom and self.lcom[nowaddr][0] == ";" and not len(self.lcom[nowaddr]) == 0:
			return self.lcom[nowaddr][1:];
		elif pastaddr in self.lcom and self.lcom[pastaddr][0] == ";" and not len(self.lcom[pastaddr]) == 0:
			return self.lcom[pastaddr][1:];
		return None;

	def getstr(self):
		result = "";
		#for sitem in self.irsb.statements:
		#	print(123);
		#	print(sitem);
		if not self.irsb == None:
			result += self.irsb._pp_str()+"\n";
			#print(dir(self.irsb));
			result += str(self.irsb.direct_next) + "\n";
			result += str(self.irsb.next) + "\n";
			nextblocks = self.getnextblockaddr();
			for b in nextblocks:
				result += b[0] + "\n";
		if self.transonce:
			result += "%s\n"%self.stack;
			result += "%s\n"%self.sprelate;
		return result;

	def getmetadata(self):
		result = "";
		if not self.irsb == None:
			result += "0x%X"%self.beginaddr;
		elif self.iscallextern:
			result += self.externfunctioncall;
			for a in self.externfunctionarg:
				result += " " + a;
		return result;

	def _pp_str(self):
		result = "";
		result += self.irsb._pp_str() + "\n";
		return result;


def deepcopyproblock(node,leafresult):
	if node == None:
		return None;
	targetnode = problock(node.irsb,node.lcom);
	lefttargetnode = None;
	righttargetnode = None;
	#print("0x%X"%node.beginaddr);
	if node.getleftchildren() == None and node.getrightchildren() == None:
		leafresult.add(targetnode);
	if not node.getleftchildren() == None:
		lefttargetnode = deepcopyproblock(node.getleftchildren(),leafresult);
		targetnode.addleftchildren(lefttargetnode);
		lefttargetnode.addparents(targetnode);
	if not node.getrightchildren() == None:
		righttargetnode = deepcopyproblock(node.getrightchildren(),leafresult);
		targetnode.addrightchildren(righttargetnode);
		righttargetnode.addparents(targetnode);
	return targetnode;
