#include <iostream>
#include "FileStream.h"

using namespace std;

//const unsigned int BUFFER_BLOCKS = 512;
const unsigned int BUFFER_BLOCKS = 1024;
//unsigned int FileSize;
//unsigned int NextSeq;

BlockList::BlockList(unsigned int size) : blockNum_(0),
                                    size_(size)
{
}

BlockList::~BlockList()
{
    list<Block>::iterator it = blockList_.begin();
    for (; it != blockList_.end(); it++) {
        delete (*it).data;
    }
    blockList_.clear();
}

bool BlockList::Insert(Block block)
{
    if (blockNum_ == size_) {
        return false;
    }
    if (blockNum_ == 0) {
        blockList_.push_front(block);
        ++blockNum_;
        minSeq_ = block.seq;
        return true;
    }
    if (block.seq < minSeq_) {
        minSeq_ = block.seq;
    }
    list<Block>::iterator it = blockList_.begin();
    for (; it != blockList_.end(); it++) {
        if (block.seq <= (*it).seq) {
            blockList_.insert(it, block);
            ++blockNum_;
            return true;
        }
    }
    blockList_.insert(it, block);
    ++blockNum_;

    return true;
}

bool BlockList::Pop(Block& block)
{
    if (blockNum_ <= 0) {
        return false;
    }
    block = *blockList_.begin(); 
    blockList_.pop_front();
    if (--blockNum_) {
        minSeq_ = (*blockList_.begin()).seq;
    } else {
        minSeq_ = 0;
    }
    return true;
}
//void FileStream::SetFileSize(unsigned int fileSize) {FileSize = fileSize;}
//void FileStream::SetNextSeq(unsigned int netSeq) {NextSeq = netSeq;}

 
FileStream::FileStream() : status_(STR_TRANS),
                           fileSize_(0),
                           nextSeq_(0),
                           file_(NULL),
                           blockList_(BUFFER_BLOCKS)

{
}



FileStream::~FileStream()
{
    if (file_) {
        file_->close();
        delete file_;
    }
}
//void FileStream::SetFileSize_(unsigned int fileSize) { fileSize_ = fileSize; cout<<"!!!: " <<fileSize_<<endl;}
bool FileStream::CreateFile(unsigned int fileSize, const char* fileName, unsigned int seq, const char* body, unsigned int bodyLen)
{
    if (fileSize < bodyLen) {
        return false;
    }
    file_ = new ofstream(fileName, ios::ate);
    if (!file_) {
//        cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file failed." << endl;
        return false;
    }
    file_->write(body, bodyLen);
   // nextSeq_ = seq + bodyLen;
    nextSeq_=seq+1;
    fileSize_ = fileSize - bodyLen;
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << endl;
    return true;
}/*
bool FileStream::CreateFile(unsigned int fileSize, const char* fileName, unsigned int pktSum, unsigned int fileNum, unsigned int seq)
{
    
    file_ = new ofstream(fileName, ios::ate);
    if (!file_) {
//        cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Create file failed." << endl;
        return false;
    }
    unsigned int bodyLen=0;
    const char* body=NULL;
    endSeq_=pktSum;
    file_->write(body, bodyLen);
    
    nextSeq_ = seq + 1;
  
    fileSize_ = fileSize - bodyLen;
   // SetFileSize(fileSize_);
    //SetNextSeq(nextSeq_);
    
//	cout << __FILE__ << ":" << __FUNCTION__ << ":" << endl;
    return true;
}*/
StreamStatus FileStream::AddData(unsigned int seq, const char* body, unsigned int bodyLen)
{
	//cout << "Packet ADDDATA:"<<endl;
	//cout << __FILE__ << ":" << __FUNCTION__ << ":" <<  " nextseq:"<< nextSeq_ << " filesize_:"<<fileSize_<<endl;
	//cout <<"确认号： " <<seq<<"    bodylen:"<<bodyLen<<endl;

	if (StoreBuf() == STR_END)
	{
		return STR_END;
	}
    if (seq == nextSeq_)
	{
		//cout<<"storetofile......"<<endl;
		LOG_DEBUG("storetofile......\n");
        return StoreToFile(body, bodyLen);
    }
	else if (seq > nextSeq_)// && seq<=endSeq_)
	{
		//cout<<"blockList_.Insert"<<endl;
		LOG_DEBUG("blockList_.Insert\n");
        char* data = new char[bodyLen];
        memcpy(data, body, bodyLen);
        if (blockList_.Insert(Block(seq, bodyLen, data)))
		{
            return STR_TRANS;
        }
		else
		{
            delete data;
            //cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Out of size" << endl;
			LOG_DEBUG("Out of size\n");
            return STR_ERR;
        }
    }
	else if(seq < nextSeq_)
	{
		//cout<<"传进来的seq 小于 netseq"<<endl;
        unsigned int offset = nextSeq_ - seq;
        if (bodyLen > offset)
		{
            return StoreToFile(body + offset, bodyLen - offset);
        }
		else {
            return STR_TRANS;
        }
    }
	//if (StoreBuf() == STR_END)
	//{
	//	return STR_END;
       // }
	if (fileSize_<=1440)
	{
		if (StoreBuf() == STR_END)
		{
			return STR_END;
		}
	}


    return STR_TRANS;
}
StreamStatus FileStream::StoreToFile(const char* body, unsigned int bodyLen)
{
    if (fileSize_ > bodyLen)
	{
		//cout << "Begin write file!" <<endl;
        file_->write(body, bodyLen);
        nextSeq_++;
        //cout << "NextSeq: "<< nextSeq_ <<endl;
        fileSize_ -= bodyLen;
        //cout << "FileSize_: "<< fileSize_ <<endl;
    }
	else {
        file_->write(body, fileSize_);
        nextSeq_ =-1;
        fileSize_ = 0;
        return STR_END;
    }


    return STR_TRANS;
}
/*


StreamStatus FileStream::AddData(unsigned int seq, const char* body, unsigned int bodyLen)
{
	//cout << "Packet ADDDATA:"<<endl;
	cout << __FILE__ << ":" << __FUNCTION__ << ":" <<  "netseq:"<< nextSeq_ << endl;
	cout <<"确认号： " <<seq<<"    bodylen:"<<bodyLen<<endl;

	if (StoreBuf() == STR_END)
	{
		return STR_END;
	}
    if (seq == nextSeq_)
	{
		cout<<"storetofile"<<endl;
        return StoreToFile(body, bodyLen);
    }
	else if (seq > nextSeq_)
	{
		cout<<"blockList_.Insert"<<endl;
        char* data = new char[bodyLen];
        memcpy(data, body, bodyLen);
        if (blockList_.Insert(Block(seq, bodyLen, data)))
		{
            return STR_TRANS;
        }
		else
		{
            delete data;
            cout << __FILE__ << ":" << __FUNCTION__ << ":" << "Out of size" << endl;
            return STR_ERR;
        }
    }
	else if(seq < nextSeq_)
	{
		cout<<"传进来的seq 小于 netseq"<<endl;
        unsigned int offset = nextSeq_ - seq;
        if (bodyLen > offset)
		{
            return StoreToFile(body + offset, bodyLen - offset);
        }
		else {
            return STR_TRANS;
        }
    }
	//if (StoreBuf() == STR_END)
	//{
	//	return STR_END;
//}
	if(fileSize_<=1440)
	{
		if (StoreBuf() == STR_END)
		{
			return STR_END;
		}
	}


    return STR_TRANS;
}

StreamStatus FileStream::StoreToFile(const char* body, unsigned int bodyLen)
{
    if (fileSize_ > bodyLen)
	{
        file_->write(body, bodyLen);
        nextSeq_ += bodyLen;
        fileSize_ -= bodyLen;
    }
	else {
        file_->write(body, fileSize_);
        nextSeq_ += fileSize_;
        fileSize_ = 0;
        return STR_END;
    }


    return STR_TRANS;
}*/

StreamStatus FileStream::StoreBuf()
{
    Block block;
    StreamStatus status;
    while (blockList_.Num() && blockList_.MinSeq() <= nextSeq_)
	{
        if (!blockList_.Pop(block))
		{
            return STR_ERR;
        }
        if (block.seq == nextSeq_)
		{
            status = StoreToFile(block.data, block.dataLen);
            delete block.data;
            if (status == STR_END)
			{
                return STR_END;
            }
        }
		else
		{
            unsigned int offset = nextSeq_ - block.seq;
            if (block.dataLen <= offset)
			{ 
                delete block.data;
                continue;
            }
			else if (StoreToFile(block.data + offset, block.dataLen - offset) == STR_END)
			{
                delete block.data;
                return STR_END;
            }
            delete block.data;
        }
    }

    return STR_TRANS;
}

// End of file
