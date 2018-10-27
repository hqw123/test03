#ifndef __BUFFER__
#define __BUFFER__

#include <iostream>
#include <queue>
#include <boost/thread/mutex.hpp>
using namespace std;

template<class T>
class Buffer
{
public:
    Buffer(u_int bufSize);
    virtual ~Buffer();
    bool Push(T data);
    T Pop();
private:
    queue<T> buffer_;
    boost::mutex bufMut_;
    u_int dataNumber_;
    u_int bufferSize_;
};


template<class T>
Buffer<T>::Buffer(u_int bufSize) : dataNumber_(0),
                                    bufferSize_(bufSize)
{
}

template<class T>
Buffer<T>::~Buffer()
{
    boost::mutex::scoped_lock lock(bufMut_);
    while (!buffer_.empty()) {
        T tmp = buffer_.front();
        buffer_.pop();
        --dataNumber_;
        delete tmp;
    }
}

template<class T>
bool Buffer<T>::Push(T data)
{
//cout<< "........push........" <<endl;
    bool pushOkay = true;
    boost::mutex::scoped_lock lock(bufMut_);
    if (dataNumber_ < bufferSize_) {
        buffer_.push(data);
        ++dataNumber_;
    } else {
        pushOkay = false;
    }

    return pushOkay;
}

template<class T>
T Buffer<T>::Pop()
{
    T ret = NULL;
    boost::mutex::scoped_lock lock(bufMut_);
    if (dataNumber_ > 0) {
        ret = buffer_.front();
        buffer_.pop();
        --dataNumber_;
    }

    return ret;
}

#endif
// End of file.
