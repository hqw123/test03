
#include <fstream>
#include <sstream>
#include <netinet/in.h>     // For ntohl().
#include <sys/stat.h>       // For mkdir().

#include "MSNFileExtractor.h"
//#include "Analyzer_log.h"

using namespace std;

//#define DIRECTORY          "/home/nodeData/moduleData/MSN"
//#define SUB_DIREC          "/home/nodeData/moduleData/MSN/File"

#define PORT_BITS          16
#define TAG                0x70050008
#define ENDTAG             0x00000608
#define TRANS_HLEN         28
#define TRANS_UDP_HLEN     48
#define TRANS_UDP_ENDHLEN  36
#define RARTAG             0x21726152
#define PDFTAG             0x46445025

//#define FILE_RULE  "^$"
MSNFileExtractor::MSNFileExtractor()
{
	sprintf(DIRECTORY,"%s%s",nodeDataPath,"/nodeData/moduleData/MSN");
	sprintf(SUB_DIREC,"%s%s",nodeDataPath,"/nodeData/moduleData/MSN/File");
	isRunning_ = true;
	isDeepParsing_ = false;
	attachSize_ = 100*1024*1024;
	miniSize_ = 0;
    protoType_ = PROTOCOL_MSNFILE;
    mkdir(DIRECTORY, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    mkdir(SUB_DIREC, S_IRWXU | S_IWGRP | S_IROTH | S_IWOTH | S_IRGRP);
    sprintf(filePath_, "%s\0", SUB_DIREC);
   //fileRule_ = new boost::regex(FILE_RULE);
}

MSNFileExtractor::~MSNFileExtractor()
{

}

bool MSNFileExtractor::IsFile(PacketInfo* pktInfo)
{
    //assert(pktInfo != NULL);
    bool isMSNFile = false;
    pktInfo_ = pktInfo;
   // if ((pktInfo_->bodyLen > TRANS_HLEN) && *reinterpret_cast<const u_int*>(pktInfo_->body) == TAG) {
    if (pktInfo_->pktType == UDP){
        isMSNFile = MatchMSNUDPFile();
	}else if (pktInfo_->destPort == 443){     
		isMSNFile = MatchMSNHTTPSFile();
        }
     else {
		 
		 isMSNFile = MatchMSNFile();
    }
    if (isMSNFile) {
        pktInfo_ = NULL;
    }

    return isMSNFile;
}

bool MSNFileExtractor::MatchMSNFile()
{
   bool matched = false;
   u_int clueId;
   if((pktInfo_->bodyLen > TRANS_HLEN) && *reinterpret_cast<const u_int*>(pktInfo_->body) == TAG){
      //cout<<"TCP TRANS"<<endl;
	  char strmac[20];
	  memset(strmac,0,20);
	  ParseMac(pktInfo_->srcMac,strmac);
	  char strmac2[20];
	  memset(strmac2,0,20);
	  ParseMac(pktInfo_->destMac,strmac2);
      char temp[100] = {0};    
    
	  clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
	  if (!clueId) {
		  matched=false;
	  }else{
      uint64_t key = pktInfo_->srcIpv4;
      key = key << PORT_BITS;
      key += pktInfo_->srcPort;
     
      char* fileSuffix;
      if(*reinterpret_cast<const u_int*>(pktInfo_->body+28) == RARTAG)
      {
       fileSuffix=".rar";
      }else if(*reinterpret_cast<const u_int*>(pktInfo_->body+28) == PDFTAG)
      {
       fileSuffix=".pdf";
      }else{
      return matched;
      }
      keyMap.insert(pair<uint64_t,char*>(key,fileSuffix));
     
      
      u_int i=28;
      while(i<pktInfo_->bodyLen)
      {
      s+=pktInfo_->body[i];
      i++;
      }
      //cout<<"SIZE: "<<s.size()<<endl;
      
     
      matched=true;
	  }
   }else  if((pktInfo_->bodyLen > TRANS_HLEN+16) && *reinterpret_cast<const u_int*>(pktInfo_->body+16) == TAG){
      //cout<<"LAN TRANS"<<endl;
	  char strmac[20];
	  memset(strmac,0,20);
	  ParseMac(pktInfo_->srcMac,strmac);
	  char strmac2[20];
	  memset(strmac2,0,20);
	  ParseMac(pktInfo_->destMac,strmac2);
            
    
	  clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
	  if (!clueId) {
		  matched=false;
	  }else{
      uint64_t key = pktInfo_->srcIpv4;
      key = key << PORT_BITS;
      key += pktInfo_->srcPort;
      
      char* fileSuffix;
      if(*reinterpret_cast<const u_int*>(pktInfo_->body+48) == RARTAG)
      {
       fileSuffix=".rar";
      }else if(*reinterpret_cast<const u_int*>(pktInfo_->body+48) == PDFTAG)
      {
       fileSuffix=".pdf";
      }else{
      return matched;
      }
      keyMap.insert(pair<uint64_t,char*>(key,fileSuffix));
     // uint32_t seq=ntohl(tcp->seq);
     // uint32_t nextSeq=seq+pktInfo_->bodyLen;
       u_int i=48;
      while(i<pktInfo_->bodyLen)
      {
      s+=pktInfo_->body[i];
      i++;
      }
      //cout<<"SIZE: "<<s.size()<<endl;
     
      matched=true;
	  }
   }   
   else{
	   char strmac[20];
	   memset(strmac,0,20);
	   ParseMac(pktInfo_->srcMac,strmac);
	   char strmac2[20];
	   memset(strmac2,0,20);
	   ParseMac(pktInfo_->destMac,strmac2);
            
    
	   clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
	   if (!clueId) {
		   matched=false;
	   }else{
   uint64_t key = pktInfo_->srcIpv4;
   key = key << PORT_BITS;
   key += pktInfo_->srcPort;
   map<uint64_t,char*>::iterator it;
   it=keyMap.find(key);
   if(it != keyMap.end())
   {  //cout<<"TRANS.."<<endl;
      
       u_int i=0;
      while(i<pktInfo_->bodyLen)
      {
      s+=pktInfo_->body[i];
      i++;
      }
     
      //cout<<"SIZE: "<<s.size()<<endl;
      
      string::size_type p=s.find("BYE");
      //cout<<"???: "<<p<<endl;
      if(p!= string::npos)
      
       
      
      {
      //cout<<"last.."<<endl;
      
     
      
     
      string filedata;
      
	  //cout<<s.size()<<endl;
	  u_int i=0;
	  while(i<p-1424){//1404+20=1424
      filedata.append(s,i,1372);
     // cout<<i<<endl;
	  i+=1404;
     // cout<<filedata.size()<<endl;
      }
      
	  //cout<<i<<endl;
     // cout<<filedata.size()<<endl;
	  
	  u_int l=*reinterpret_cast<const u_int*>(&s[i-32]);//i-1404+1372=i-32
     
      //cout<<"L: "<<l<<endl;
      filedata.append(s,i-32+20,l-16);
      u_int bodyLen=filedata.size();
	  /*const char* sql2="select mini_size from protocol_set where protocolid = :v1";
	  oracle::occi::Statement* stmt2_;
	  stmt2_= occi_->CreateStmt();
	  occi_->SetSql(stmt2_, sql2);
	  occi_->SetInt(stmt2_, 1, PROTOCOL_ID_MSNFILE);
	  u_int minSize=occi_->DoSqlRetInt(stmt2_);
	  occi_->TerminateStmt(stmt2_);
	  cout<<"MINSize"<<minSize<<endl;
	  const char* sql1="select attach_size from protocol_set where protocolid = :v1";
	  oracle::occi::Statement* stmt1_;
	  stmt1_= occi_->CreateStmt();
	  occi_->SetSql(stmt1_, sql1);
	  occi_->SetInt(stmt1_, 1, PROTOCOL_ID_MSNFILE);
	  u_int maxSize=occi_->DoSqlRetInt(stmt1_);
	  occi_->TerminateStmt(stmt1_);
	  cout<<"MAXSize"<<maxSize<<endl;*/
	  if(bodyLen<miniSize_||bodyLen>attachSize_)
	  {
		  return matched;
	  }
     // cout<<"fileSize: "<<bodyLen<<endl;
	  
	  time_t currentTime;
	  time(&currentTime);
	  char* fname;
	  map<uint64_t,char*>::iterator ite;
	  for(ite=keyMap.begin();ite!=keyMap.end();ite++)
	  {
		  fname=ite->second;
	  }
      
	  char* fileName_ = new char[512];
	  sprintf(fileName_,"%s/%lu%s\0",filePath_,currentTime,fname);
	  //sprintf(fileName_,"%s/%lu\0",filePath_,currentTime);
	  file_= new ofstream(fileName_, ios::ate);
	 // cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file end,then begin write file..." <<endl;
	 LOG_INFO("Create file end,then begin write file...\n");
      char* body=new char[bodyLen];
      
     // strcpy(body,filedata.c_str());
	  memcpy(body,&filedata[0],bodyLen);
      file_->write(body,bodyLen);
      file_->close();
	 // cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Write file end!" <<endl;
	 LOG_INFO("Write file end!\n");
	  //store case data to DB
	  char strmac[20];
	  memset(strmac,0,20);
	  ParseMac(pktInfo_->srcMac,strmac);
	  char strmac2[20];
	  memset(strmac2,0,20);
	  ParseMac(pktInfo_->destMac,strmac2);
            
    
             //clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
              //cout<< "CLUEID: "<<clueId<<endl; 
	  u_int clueid = GetClueId(protoType_, strmac ,pktInfo_->srcIpv4);
	  u_int type;
	  if(!clueId)
	  {
		  clueid=GetClueId(protoType_, strmac2,pktInfo_->destIpv4);
		  type=2;
	  }
	  else{
		  type=1;
	  }
              //cout<< "CLUEID: "<<clueId<<endl; 
              //cout<<"TYPE: "<<type<<endl;
	  protoId_ = PROTOCOL_ID_MSNFILE;
	  u_int devNum_ = GetDeviceNum();
        
	  u_short srcport = pktInfo_->srcPort;
	  u_short destport = pktInfo_->destPort;
		struct in_addr addr;
#if 0
	  string sql = "insert into IMINFO(id,clueid,readed,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,num,peernum,type,deleted) ";
	  sql += "values(SEQ_IMINFO_ID.nextval,:clueid,:readed,:clientip,:clientmac,:clientport,:serverip,:serverport,:capturetime,:optype,:content,:num,:peernum,:type,:deleted)";

	 	sqlConn_->SetSql(sql.c_str());
	 	sqlConn_->SetInt(1, clueid);
	 	sqlConn_->SetInt(2, 0);
	 	addr.s_addr = pktInfo_->srcIpv4;   
	 	sqlConn_->SetString(3, inet_ntoa(addr));
	 	sqlConn_->SetString(4, strmac);
		sprintf(temp,"%d",srcport);
	 	sqlConn_->SetString(5, srcport);
		addr.s_addr = pktInfo_->destIpv4;   
	 	sqlConn_->SetString(6, inet_ntoa(addr));
		sprintf(temp,"%d",destport);
	 	sqlConn_->SetString(7, temp);
		sqlConn_->SetTime(8, time(NULL));
		sqlConn_->SetInt(9,0);          
	 	sqlConn_->SetString(10, "");
	 	sqlConn_->SetString(11, "");
	 	sqlConn_->SetString(12, "");
		sqlConn_->SetInt(13, protoId_);  //PROTOCOL_ID_MSNFILE
	 	sqlConn_->SetInt(14, 0);
	 	sqlConn_->DoSql();
#endif

#if 0  //zhangzm	   
	  const char* sql="insert into IMTRANSFER (imtransferid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, datafile, fsize, type) values (imtransferid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12)";
       
	  stmt_= occi_->CreateStmt();
	  occi_->SetSql(stmt_, sql);
	  occi_->SetInt(stmt_, 1, devNum_);
	  occi_->SetInt(stmt_, 2, clueid);
	  struct in_addr addr;
	  addr.s_addr = pktInfo_->srcIpv4;   
	  occi_->SetString(stmt_, 3, inet_ntoa(addr));  
	  occi_->SetInt(stmt_, 4, srcport);
	  addr.s_addr = pktInfo_->destIpv4;   
	  occi_->SetString(stmt_, 5, inet_ntoa(addr));  
	  occi_->SetInt(stmt_, 6, destport);
	  time_t timeVal;
	  time(&timeVal);
	  occi_->SetTime(stmt_, 7, timeVal);
	  occi_->SetString(stmt_, 8, strmac);
        //cout<<"path: "<<fileName_<<endl;
	  occi_->SetInt(stmt_, 9, type); 
	  occi_->SetString(stmt_, 10,fileName_); 
	  occi_->SetInt(stmt_, 11,bodyLen); 
	  occi_->SetInt(stmt_, 12, protoId_); 
	  cout << "[MSNFILETRANGSFER]: Data for case!The clueid is "<< clueId << endl;
	  occi_->DoSql(stmt_);
              
            
	  occi_->TerminateStmt(stmt_);  
#endif
	  delete fileName_;
	  delete body;
      s.clear();
      filedata.clear();
      keyMap.clear();
     // cout<<"end..."<<endl;
      }
      matched=true;
   }
   }
   }
   return matched;
}
bool MSNFileExtractor::MatchMSNHTTPSFile()
{
	bool matched = false;
	u_int clueId;
	if((pktInfo_->bodyLen > TRANS_HLEN+8) && *reinterpret_cast<const u_int*>(pktInfo_->body+8) == TAG){
		//cout<<"HTTPS TRANS"<<endl;
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->srcMac,strmac);
		char strmac2[20];
		memset(strmac2,0,20);
		ParseMac(pktInfo_->destMac,strmac2);
            
    
		clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
		if (!clueId) {
			matched=false;
		}else{
			uint64_t key = pktInfo_->srcIpv4;
			key = key << PORT_BITS;
			key += pktInfo_->srcPort;
      
			char* fileSuffix;
			if(*reinterpret_cast<const u_int*>(pktInfo_->body+36) == RARTAG)
			{
				fileSuffix=".rar";
			}else if(*reinterpret_cast<const u_int*>(pktInfo_->body+36) == PDFTAG)
			{
				fileSuffix=".pdf";
			}else{
			return matched;
			}
			keyMap.insert(pair<uint64_t,char*>(key,fileSuffix));
     
			u_int i=36;
			while(i<pktInfo_->bodyLen)
			{
				s+=pktInfo_->body[i];
				i++;
			}
			//cout<<"SIZE: "<<s.size()<<endl;
     
			matched=true;
		}
	}   
	else{
		char strmac[20];
		memset(strmac,0,20);
		ParseMac(pktInfo_->srcMac,strmac);
		char strmac2[20];
		memset(strmac2,0,20);
		ParseMac(pktInfo_->destMac,strmac2);
            
    
		clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
		if (!clueId) {
			matched=false;
		}else{
			uint64_t key = pktInfo_->srcIpv4;
			key = key << PORT_BITS;
			key += pktInfo_->srcPort;
			map<uint64_t,char*>::iterator it;
			it=keyMap.find(key);
			if(it != keyMap.end())
			{  //cout<<"TRANS.."<<endl;
     
			u_int i=0;
			while(i<pktInfo_->bodyLen)
			{
				s+=pktInfo_->body[i];
				i++;
			}
      
			//cout<<"SIZE: "<<s.size()<<endl;
      
			string::size_type p=s.find("BYE");
			//cout<<"???: "<<p<<endl;
			if(p!= string::npos)
      
       
      
			{
				//cout<<"last.."<<endl;
				
     
      
     
				string filedata;
				
				//cout<<s.size()<<endl;
				u_int i=0;
				while(i<p-1432){//1408+24=1432
					filedata.append(s,i,1372);
					//cout<<i<<endl;
					i+=1408;
					//cout<<filedata.size()<<endl;
				}
      
				//cout<<i<<endl;
				//cout<<filedata.size()<<endl;
	  
				u_int l=*reinterpret_cast<const u_int*>(&s[i-36]);//i-1408+1372=i-36
     
				//cout<<"L: "<<l<<endl;
				filedata.append(s,i-36+24,l-16);
				u_int bodyLen=filedata.size();
				/*const char* sql2="select mini_size from protocol_set where protocolid = :v1";
				oracle::occi::Statement* stmt2_;
				stmt2_= occi_->CreateStmt();
				occi_->SetSql(stmt2_, sql2);
				occi_->SetInt(stmt2_, 1, PROTOCOL_ID_MSNFILE);
				u_int minSize=occi_->DoSqlRetInt(stmt2_);
				occi_->TerminateStmt(stmt2_);
				cout<<"MINSize"<<minSize<<endl;
				const char* sql1="select attach_size from protocol_set where protocolid = :v1";
				oracle::occi::Statement* stmt1_;
				stmt1_= occi_->CreateStmt();
				occi_->SetSql(stmt1_, sql1);
				occi_->SetInt(stmt1_, 1, PROTOCOL_ID_MSNFILE);
				u_int maxSize=occi_->DoSqlRetInt(stmt1_);
				occi_->TerminateStmt(stmt1_);
				cout<<"MAXSize"<<maxSize<<endl;*/
				if(bodyLen<miniSize_||bodyLen>attachSize_)
				{
					return matched;
				}
				//cout<<"fileSize: "<<bodyLen<<endl;
				time_t currentTime;
				time(&currentTime);
				char* fname;
				map<uint64_t,char*>::iterator ite;
				for(ite=keyMap.begin();ite!=keyMap.end();ite++)
				{
					fname=ite->second;
				}
      
				char* fileName_ = new char[512];
				sprintf(fileName_,"%s/%lu%s\0",filePath_,currentTime,fname);
	  //sprintf(fileName_,"%s/%lu\0",filePath_,currentTime);
				file_= new ofstream(fileName_, ios::ate);
				cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file end,then begin write file..." <<endl;
				char* body=new char[bodyLen];
      
     // strcpy(body,filedata.c_str());
				memcpy(body,&filedata[0],bodyLen);
				file_->write(body,bodyLen);
				file_->close();
				cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Write file end!" <<endl;
	  //store case data to DB
				char strmac[20];
				memset(strmac,0,20);
				ParseMac(pktInfo_->srcMac,strmac);
				char strmac2[20];
				memset(strmac2,0,20);
				ParseMac(pktInfo_->destMac,strmac2);
            
    
             //clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
              //cout<< "CLUEID: "<<clueId<<endl; 
				u_int clueid = GetClueId(protoType_, strmac ,pktInfo_->srcIpv4);
				u_int type;
				if(!clueId)
				{
					clueid=GetClueId(protoType_, strmac2,pktInfo_->destIpv4);
					type=2;
				}
				else{
					type=1;
				}
              //cout<< "CLUEID: "<<clueId<<endl; 
              //cout<<"TYPE: "<<type<<endl;
				protoId_ = PROTOCOL_ID_MSNFILE;
				u_int devNum_ = GetDeviceNum();
        
				u_short srcport = pktInfo_->srcPort;
				u_short destport = pktInfo_->destPort;
#if 0
				string sql = "insert into IMINFO(id,clueid,readed,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,num,peernum,type,deleted) ";
				sql += "values(SEQ_IMINFO_ID.nextval,:clueid,:readed,:clientip,:clientmac,:clientport,:serverip,:serverport,:capturetime,:optype,:content,:num,:peernum,:type,:deleted)";

				  sqlConn_->SetSql(sql.c_str());
				  sqlConn_->SetInt(1, param);
				  sqlConn_->SetInt(2, param);
				  sqlConn_->SetInt(9, param);
				  sqlConn_->SetInt(13, protoId_);
				  sqlConn_->SetInt(14, 0);

				  sqlConn_->SetTime(8, param);
				  sqlConn_->SetString(3, param);
				  sqlConn_->SetString(4, param);
				  sqlConn_->SetString(5, param);
				  sqlConn_->SetString(6, param);
				  sqlConn_->SetString(7, param);
				  sqlConn_->SetString(10, param);
				  sqlConn_->SetString(11, param);
				  sqlConn_->SetString(12, param);
				  sqlConn_->DoSql();
#endif

#if 0       //zhangzm
				const char* sql="insert into IMTRANSFER (imtransferid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, datafile, fsize, type) values (imtransferid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12)";
       
				stmt_= occi_->CreateStmt();
				occi_->SetSql(stmt_, sql);
				occi_->SetInt(stmt_, 1, devNum_);
				occi_->SetInt(stmt_, 2, clueid);
				struct in_addr addr;
				addr.s_addr = pktInfo_->srcIpv4;   
				occi_->SetString(stmt_, 3, inet_ntoa(addr));  
				occi_->SetInt(stmt_, 4, srcport);
				addr.s_addr = pktInfo_->destIpv4;   
				occi_->SetString(stmt_, 5, inet_ntoa(addr));  
				occi_->SetInt(stmt_, 6, destport);
				time_t timeVal;
				time(&timeVal);
				occi_->SetTime(stmt_, 7, timeVal);
				occi_->SetString(stmt_, 8, strmac);
        //cout<<"path: "<<fileName_<<endl;
				occi_->SetInt(stmt_, 9, type); 
				occi_->SetString(stmt_, 10,fileName_); 
				occi_->SetInt(stmt_, 11,bodyLen); 
				occi_->SetInt(stmt_, 12, protoId_); 
				cout << "[MSNFILETRANGSFER]: Data for case!The clueid is "<< clueId << endl;
				occi_->DoSql(stmt_);
              
            
				occi_->TerminateStmt(stmt_);  
#endif
				delete fileName_;
				delete body;
				s.clear();
				filedata.clear();
				keyMap.clear();
				//cout<<"end..."<<endl;
			}
			matched=true;
			}
		}
	}
	return matched;
}

bool MSNFileExtractor::MatchMSNUDPFile()
{
   bool matched = false;
   u_int clueId;
   if((pktInfo_->bodyLen > TRANS_UDP_HLEN) && *reinterpret_cast<const u_int*>(pktInfo_->body+20) == TAG)
   {
      //cout<<"UDP TRANS"<<endl;
	  char strmac[20];
	  memset(strmac,0,20);
	  ParseMac(pktInfo_->srcMac,strmac);
	  char strmac2[20];
	  memset(strmac2,0,20);
	  ParseMac(pktInfo_->destMac,strmac2);
            
    
	  clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
	  if (!clueId) {
		  matched=false;
	  }else{
      uint64_t key = pktInfo_->srcIpv4;
      key = key << PORT_BITS;
      key += pktInfo_->srcPort;
      map<uint64_t,char*>::iterator it;
      it=keyMap.find(key);
      if(it != keyMap.end()){
     
      u_int num=*reinterpret_cast<const u_int*>(pktInfo_->body);
      //cout<<"NUM: "<<num<<endl;
      u_int bodyLen_=pktInfo_->bodyLen-48;
      char* body=new char[bodyLen_];
      //memset(body,0,bodyLen_+1);
      memcpy(body,pktInfo_->body+48,bodyLen_);
      MSNUDPFile file;
      file.filebodylen=bodyLen_;
      file.filebody=body;
      my_map.insert(map<u_int,MSNUDPFile>::value_type(num,file));
      matched = true ;
      }else
      {
       
      char* fileSuffix;
      if(*reinterpret_cast<const u_int*>(pktInfo_->body+48) == RARTAG)
      {
       fileSuffix=".rar";
      }else if(*reinterpret_cast<const u_int*>(pktInfo_->body+48) == PDFTAG)
      {
       fileSuffix=".pdf";
      }else{
      return matched;
      }
      keyMap.insert(pair<uint64_t,char*>(key,fileSuffix));
       u_int num=*reinterpret_cast<const u_int*>(pktInfo_->body);
       //cout<<"NUM: "<<num<<endl;
      u_int bodyLen_=pktInfo_->bodyLen-TRANS_UDP_HLEN;
      char* body=new char[bodyLen_];
      //memset(body,0,bodyLen_+1);
      memcpy(body,pktInfo_->body+48,bodyLen_);
      MSNUDPFile file;
      file.filebodylen=bodyLen_;
      file.filebody=body;
      my_map.insert(map<u_int,MSNUDPFile>::value_type(num,file));
      matched = true ;
	  }
      }
   }
   if ((pktInfo_->bodyLen > TRANS_UDP_ENDHLEN) && *reinterpret_cast<const u_int*>(pktInfo_->body+28) == ENDTAG)
   {  char strmac[20];
   memset(strmac,0,20);
   ParseMac(pktInfo_->srcMac,strmac);
   char strmac2[20];
   memset(strmac2,0,20);
   ParseMac(pktInfo_->destMac,strmac2);
            
    
   clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
             //cout<< "CLUEID: "<<clueId<<endl;
    
   if (!clueId) {
	   matched=false;
   }else{
      uint64_t key = pktInfo_->srcIpv4;
      key = key << PORT_BITS;
      key += pktInfo_->srcPort;
      map<uint64_t,char*>::iterator it;
      it=keyMap.find(key);
      if(it != keyMap.end()){
      u_int num=*reinterpret_cast<const u_int*>(pktInfo_->body);
     // cout<<"NUM: "<<num<<endl;
      u_int bodyLen_=pktInfo_->bodyLen-36;
      char* body=new char[bodyLen_];
     // memset(body,0,bodyLen_+1);
      memcpy(body,pktInfo_->body+36,bodyLen_);
      MSNUDPFile file;
      file.filebodylen=bodyLen_;
      file.filebody=body;
      my_map.insert(map<u_int,MSNUDPFile>::value_type(num,file));
      
      time_t currentTime;
      time(&currentTime);
      char* fname;
      map<uint64_t,char*>::iterator ite;
      for(ite=keyMap.begin();ite!=keyMap.end();ite++)
      {
       fname=ite->second;
      }
      char* fileName_ = new char[512];
      sprintf(fileName_,"%s/%lu%s\0",filePath_,currentTime,fname);
    
      file_= new ofstream(fileName_, ios::ate);
      
      
	 // cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file end,then begin write file..." <<endl;
	 LOG_INFO("Create file end,then begin write file...\n");
      map<u_int,MSNUDPFile>::iterator iter;
	  u_int fsize=0;
      for(iter=my_map.begin();iter!=my_map.end();iter++)
      {
      file_->write(iter->second.filebody,iter->second.filebodylen);
	  fsize+=iter->second.filebodylen;
      delete iter->second.filebody;
      }
      file_->close();
	  //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Write file end!" <<endl;
	  LOG_INFO("Write file end!\n");
	
	  if(fsize<miniSize_||fsize>attachSize_)
	  {
		  char rfile[512];
		  sprintf(rfile,"%s",fileName_);
		  //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Not in the scope of filesize!Delete it!" <<endl;
		  LOG_INFO("Not in the scope of filesize!Delete it!\n");
		  ::remove(rfile);
		  
		  return matched;
	  }
	  //store case data to DB
	  char strmac[20];
	  memset(strmac,0,20);
	  ParseMac(pktInfo_->srcMac,strmac);
	  char strmac2[20];
	  memset(strmac2,0,20);
	  ParseMac(pktInfo_->destMac,strmac2);
            
    
             //clueId = (GetClueId(protoType_, strmac ,pktInfo_->srcIpv4)|GetClueId(protoType_, strmac2,pktInfo_->destIpv4));
              //cout<< "CLUEID: "<<clueId<<endl; 
	  u_int clueid = GetClueId(protoType_, strmac ,pktInfo_->srcIpv4);
	  u_int type;
	  if(!clueId)
	  {
		  clueid=GetClueId(protoType_, strmac2,pktInfo_->destIpv4);
		  type=2;
	  }
	  else{
		  type=1;
	  }
              //cout<< "CLUEID: "<<clueId<<endl; 
              //cout<<"TYPE: "<<type<<endl;
	  protoId_ = PROTOCOL_ID_MSNFILE;
	  u_int devNum_ = GetDeviceNum();
        
	  u_short srcport = pktInfo_->srcPort;
	  u_short destport = pktInfo_->destPort;

//		string sql = "insert into IMINFO(id,clueid,readed,clientip,clientmac,clientport,serverip,serverport,capturetime,optype,content,num,peernum,type,deleted) ";
//		sql += "values(SEQ_IMINFO_ID.nextval,:clueid,:readed,:clientip,:clientmac,:clientport,:serverip,:serverport,:capturetime,:optype,:content,:num,:peernum,:type,:deleted)";
/*
		  sqlConn_->SetSql(sql.c_str());
		  sqlConn_->SetInt(1, param);
		  sqlConn_->SetInt(2, param);
		  sqlConn_->SetInt(9, param);
		  sqlConn_->SetInt(13, protoId_);  //PROTOCOL_ID_MSNFILE
		  sqlConn_->SetInt(14, 0);

		  sqlConn_->SetTime(8, param);
		  sqlConn_->SetString(3, param);
		  sqlConn_->SetString(4, param);
		  sqlConn_->SetString(5, param);
		  sqlConn_->SetString(6, param);
		  sqlConn_->SetString(7, param);
		  sqlConn_->SetString(10, param);
		  sqlConn_->SetString(11, param);
		  sqlConn_->SetString(12, param);
		  sqlConn_->DoSql();

*/
#if 0  //zhangzm
	  const char* sql="insert into IMTRANSFER (imtransferid, devicenum, clueid, clientip, clientport, serverip, serverport, capturetime, clientmac, optype, datafile, fsize, type) values (imtransferid.nextval, :v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, :v12)";
       
	  stmt_= occi_->CreateStmt();
	  occi_->SetSql(stmt_, sql);
	  occi_->SetInt(stmt_, 1, devNum_);
	  occi_->SetInt(stmt_, 2, clueid);
	  struct in_addr addr;
	  addr.s_addr = pktInfo_->srcIpv4;   
	  occi_->SetString(stmt_, 3, inet_ntoa(addr));  
	  occi_->SetInt(stmt_, 4, srcport);
	  addr.s_addr = pktInfo_->destIpv4;   
	  occi_->SetString(stmt_, 5, inet_ntoa(addr));  
	  occi_->SetInt(stmt_, 6, destport);
	  time_t timeVal;
	  time(&timeVal);
	  occi_->SetTime(stmt_, 7, timeVal);
	  occi_->SetString(stmt_, 8, strmac);
        //cout<<"path: "<<fileName_<<endl;
	  occi_->SetInt(stmt_, 9, type); 
	  occi_->SetString(stmt_, 10,fileName_); 
	  occi_->SetInt(stmt_, 11,fsize); 
	  occi_->SetInt(stmt_, 12, protoId_); 
	  cout << "[MSNFILETRANGSFER]: Data for case!The clueid is "<< clueId << endl;
	  occi_->DoSql(stmt_);
              
            
	  occi_->TerminateStmt(stmt_); 
#endif
	  delete fileName_;
      my_map.clear();
      keyMap.clear();
      matched = true ;
	  }
      }
   }
   return matched;
}


void MSNFileExtractor::StoreMsg2DB(MsgNode* msgNode)
{
}
