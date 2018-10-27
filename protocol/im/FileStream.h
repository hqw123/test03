#ifndef FILE_STREAM
#define FILE_STREAM

#include <fstream>
#include <list>


enum StreamStatus
{
    STR_TRANS = 1,
    STR_END,
    STR_ERR
};

struct Block
{
    Block() { }
    Block(unsigned int seq_, unsigned int dataLen_, const char* data_) { seq = seq_; dataLen = dataLen_; data = data_; }
    Block(const Block& block) { seq = block.seq; dataLen = block.dataLen; data = block.data; }
    unsigned int seq;
    unsigned int dataLen;
    const char* data;
};

class BlockList
{
public:
    BlockList(unsigned int size);
    virtual ~BlockList();
    bool Insert(Block block);
    bool Pop(Block& block);
    unsigned int MinSeq() { return minSeq_; }
    unsigned int Num() { return blockNum_; }
private:
    std::list<Block> blockList_;
    unsigned int blockNum_;
    unsigned int size_;
    unsigned int minSeq_;
};

class FileStream
{
public:
    FileStream();
   
    virtual ~FileStream();
    //bool CreateFile(unsigned int fileSize, const char* fileName, unsigned int pktSum, unsigned int fileNum, unsigned int seq);
    bool CreateFile(unsigned int fileSize, const char* fileName, unsigned int seq, const char* body, unsigned int bodyLen);
    StreamStatus AddData(unsigned int seq, const char* body, unsigned int bodyLen);
   //void SetFileSize(unsigned int fileSize);
   //void SetNextSeq(unsigned int netSeq);
   
private:
    StreamStatus StoreToFile(const char* body, unsigned int bodyLen);
    StreamStatus StoreBuf();
private:
    StreamStatus status_;
    unsigned int fileSize_;
    unsigned int endSeq_;
    unsigned int nextSeq_;
    std::ofstream* file_;
    BlockList blockList_;
    
};

#endif

// End of file
