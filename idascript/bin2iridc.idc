#include <idc.idc>


static listfunction(filename){
	auto str;
	auto ea;
	auto begin;
	auto end;
	ea = 0x0;
	auto wfd = fopen(filename,"a");
	fprintf(wfd,"all function:\n");
	while(ea != BADADDR){
                str = GetFunctionName(ea);
                if(str == 0 || strstr(SegName(ea),"extern") != -1 || strstr(SegName(ea),"plt") != -1 || strstr(SegName(ea),"stubs") != -1){
                        ea = NextFunction(ea);
                        continue;
                }
                //auto dl = GetType(ea);
                //fprintf(wfd,"0x%X\t%s %s",ea,str,dl);
                fprintf(wfd,"0x%X\t%s",ea,str);
                begin = ea; 
                end = FindFuncEnd(ea);
                while(begin < end){
                        begin = FindText(begin,SEARCH_DOWN,10,0,"sp");
                        if(begin == -1){
                                break;
                        }
                        if(strstr(GetMnem(begin),"add") != -1 || strstr(GetMnem(begin),"ADD") != -1 || strstr(GetMnem(begin),"sub") != -1 || strstr(GetMnem(begin),"SUB") != -1 || strstr(GetMnem(begin),"STM") != -1 || strstr(GetMnem(begin),"MOV") != -1 || strstr(GetMnem(begin),"mov") != -1){ 
                                if(GetOpnd(begin,0) == "SP" || GetOpnd(begin,0) == "sp" || GetOpnd(begin,0) == "$sp" || GetOpnd(begin,0) == "$SP" || GetOpnd(begin,0) == "SP!" ){
                                        fprintf(wfd,":0x%X",begin);
                                        break;
                                }
                        }
                        begin = begin + ItemSize(begin);
                }
                fprintf(wfd,"\n");
                ea = NextFunction(ea);
        }
	fclose(wfd);
}

static calltofunction(filename){
	auto str,end,begin;
	auto ea;
	ea = 0x0;
	auto wfd = fopen(filename,"a");
	fprintf(wfd,"lcom\n");
	while(ea != BADADDR){
		str = GetFunctionName(ea);
		begin = ea;
		if(str != 0 && SegName(ea) != "extern" && SegName(ea) != ".plt" && strstr(SegName(ea),"stubs") == -1){
			end = FindFuncEnd(ea);
			fprintf(wfd,"-----------------\n0x%X 0x%x %s \n",ea,end,str);
		}
		while(begin < end){
			auto dl = GetDisasm(begin);
			auto s = strstr(dl,";");
			auto lcom = substr(dl,s+1,strlen(dl));
			while(strstr(lcom," ") != -1){
				lcom = substr(lcom,strstr(lcom," ")+1,strlen(lcom));
			}
			if(s != -1){
				fprintf(wfd,"0x%X ;%s\n",begin,lcom);
				begin =begin+ ItemSize(begin);
				continue;
			}
			dl = GetDisasm(begin);
			s = strstr(dl,"#");
			lcom = substr(dl,s+1,strlen(dl));
			while(strstr(lcom," ") != -1){
				lcom = substr(lcom,strstr(lcom," ")+1,strlen(lcom));
			}
			if(s != -1){
				fprintf(wfd,"0x%X #%s\n",begin,lcom);
				begin =begin+ ItemSize(begin);
				continue;
			}
			begin =begin+ ItemSize(begin);
		}
		ea = NextFunction(ea);
	}
	fclose(wfd);
}

static printfname(filename){
	auto sourcefile;
	auto wfd;
	sourcefile = GetInputFilePath();
	wfd = fopen(filename,"w");
	fprintf(wfd,"%s\n",sourcefile);
	fclose(wfd);
}

static getpltfunctiontype(filename){
	auto wfd,ea,str;
	auto segend;
	auto segbegin;
	auto dl;
	auto ft;
	wfd = fopen(filename,"a");
	fprintf(wfd,"pltfunctiontype\n");
	ea = 0x0;
	while(ea != BADADDR ){
		str = GetFunctionName(ea);
		if(str != 0 && (SegName(ea) == ".plt" || strstr(SegName(ea),"stubs") != -1)){
			ft = trim(GetType(ea));
			fprintf(wfd,"0x%X\t%s\t%s\n",ea,str,ft);
		}
		ea = NextFunction(ea);
	}
	ea = FirstSeg();
	while(ea != BADADDR){
		if(strstr(SegName(ea),"got") != -1 || strstr(SegName(ea),"extern" ) != -1){
			segend = SegEnd(ea);
			segbegin = ea;
			while(segbegin < segend){
				dl = GetDisasm(segbegin);
				if(strstr(dl,".word") != -1){
					dl = ltoa(Dword(segbegin),16);
				}
				if(strstr(dl,".extern") != -1){
					dl = substr(dl,strstr(dl,".extern") + 7 , strlen(dl));
				}
				if(strstr(dl,".got") != -1){
					dl = substr(dl,strstr(dl,".got") + 4 , strlen(dl));
				}
				ft = GetType(segbegin);
				fprintf(wfd,"0x%X\t%s\t%s\n",segbegin,dl,ft);
				segbegin = segbegin + ItemSize(segbegin);	
			}
		}
		ea = NextSeg(ea);
	}
	fclose(wfd);
}

static listdata(segname,filename){
        auto selector;
        auto segea;
        auto segend;
        auto itemend;
	auto wfd;
	wfd = fopen(filename,"a");
        selector = SegByName(segname);
        segea = SegByBase(selector);
        segend = SegEnd(segea);
        fprintf(wfd,"%s\n",segname);
        while(segea < segend){
                auto dl = GetDisasm(segea);
		if(strstr(dl,"ALIGN") == 0){
                	segea = segea + ItemSize(segea);
			continue;
		}
                fprintf(wfd,"0x%X\t%s\n",segea,dl);
                segea = segea + ItemSize(segea);
        }
	fclose(wfd);
}

static getalldata(filename){
        listdata(".rodata",filename);
        listdata(".data",filename);
}


static getfunctiondata(filename){
        auto functionbegin;
        auto functionend;
        auto str;
        auto begin, end;
	auto wfd;
	wfd = fopen(filename,"a");
        functionbegin = 0x0;
        functionbegin = NextFunction(functionbegin);
	
        fprintf(wfd,"functionenddata\n");
        while(functionbegin != BADADDR){
                str = GetFunctionName(functionbegin);
                if( str == 0 || SegName(functionbegin) != ".text"){
                        functionbegin = NextFunction(functionbegin);
                        continue;
                }
                functionend = FindFuncEnd(functionbegin);
                functionbegin = NextFunction(functionbegin);
                begin = functionend;
                end = functionbegin;
                while(begin < end){
                        auto dl = GetDisasm(begin);
                        if(strstr(dl,"DC") != 0){ 
                                begin = begin + ItemSize(begin);
                                continue;
                        }
			if(Dfirst(begin) != -1){
				fprintf(wfd,"0x%X\t%d\n",begin,Dfirst(begin));
			}else{
                        	fprintf(wfd,"0x%X\t%s\n",begin,dl);
			}
                        begin = begin + ItemSize(begin);
                }
        }
	fclose(wfd);
}


static main() 
{
	if(ARGV.count < 2){
		Exit(-1);
	}
	auto filename;
	filename = ARGV[1];
	printfname(filename);
	listfunction(filename);
	calltofunction(filename);
	getpltfunctiontype(filename);
	getalldata(filename);
	getfunctiondata(filename);
	Exit(0);
}
