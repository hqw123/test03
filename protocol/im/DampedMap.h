#ifndef DAMPED_MAP
#define DAMPED_MAP
#include <iostream>
#include <map>
#include <boost/thread/mutex.hpp>
#include "threadpool/include/threadpool.hpp"

using namespace std;
typedef boost::mutex::scoped_lock Lock;

class DampedData
{
public:
    DampedData();
    virtual ~DampedData() { /*Lock lock(countMut_);*/ }
    u_short Increase();
    void SetZero();
    void Hold();
    void Release();
    bool IsUsing();
private:
    u_short dampedCount_;
    boost::mutex countMut_;
    bool using_;
};

template <class Key>
class DampedMap
{
public:
    DampedMap(unsigned int maxNum, u_short checkTime, u_short delTimes);
    virtual ~DampedMap();
    bool Push(Key key, DampedData* data);
    DampedData* Find(Key key);
    void Update(Key key);
    bool Pop(Key key);
    bool IsLooping() { return looping_; }
    void CheckMap();
private:
    static void LoopDecrease(void* obj);
private:
    map<Key, DampedData*> dampedMap_;
    boost::mutex mapMut_;
    unsigned int maxNum_;
    unsigned int dataNum_;
    bool looping_;
    boost::threadpool::pool threadPool_;
    typename map<Key, DampedData*>::iterator* clearIt_;
    u_short clearNum_;
    u_short delTimes_;
    static u_short checkTime_;
};

template <class Key>
u_short DampedMap<Key>::checkTime_;

template <class Key>
DampedMap<Key>::DampedMap(unsigned int maxNum, u_short checkTime, u_short delTimes) : maxNum_(maxNum),
                                                                                dataNum_(0),
                                                                                looping_(true),
                                                                                delTimes_(delTimes)
{
    DampedMap<Key>::checkTime_ = checkTime;
    threadPool_.size_controller().resize(1);
    threadPool_.schedule(boost::bind(&LoopDecrease, this));
    clearIt_ = new typename map<Key, DampedData*>::iterator[maxNum_];
    clearNum_ = 0;
}

template <class Key>
DampedMap<Key>::~DampedMap()
{
	//cout << __FILE__ << ":" << __FUNCTION__ << endl;
    looping_ = false;
    threadPool_.wait();
    typename map<Key, DampedData*>::iterator it;
    Lock lock(mapMut_);
    it = dampedMap_.begin();
    for (; it != dampedMap_.end(); ++it) {
        delete it->second;
    }
    dampedMap_.clear();
}

template <class Key>
bool DampedMap<Key>::Push(Key key, DampedData* dampedData)
{
    //assert(dampedData != NULL);
	if (dampedData == NULL)
		return false;
	
    bool pushOkay = false;
    if (dataNum_ < maxNum_) {
        pushOkay = true;
        Pop(key);
        ++dataNum_;
        Lock lock(mapMut_);
        dampedMap_[key] = dampedData;
    }

    return pushOkay;
}

template <class Key>
DampedData* DampedMap<Key>::Find(Key key)
{
    DampedData* dampedData = NULL;
    typename map<Key, DampedData*>::iterator it;
    {
        Lock lock(mapMut_);
        it = dampedMap_.find(key);
        if (it != dampedMap_.end()) {
            dampedData = it->second;
            dampedData->Hold();
        }
    }

    return dampedData;
}

template <class Key>
void DampedMap<Key>::Update(Key key)
{
    typename map<Key, DampedData*>::iterator it;
    Lock lock(mapMut_);
    it = dampedMap_.find(key);
    if (it != dampedMap_.end()) {
        it->second->SetZero();
    }
}

template <class Key>
bool DampedMap<Key>::Pop(Key key)
{
    bool popOkay = false;
    typename map<Key, DampedData*>::iterator it;
    {
        Lock lock(mapMut_);
        it = dampedMap_.find(key);
        if (it != dampedMap_.end()) {
            delete it->second;
            dampedMap_.erase(it);
            --dataNum_;
            popOkay = true;
        }
    }

    return popOkay;
}

template <class Key>
void DampedMap<Key>::LoopDecrease(void* obj)
{
    DampedMap<Key>* dampedMap = reinterpret_cast<DampedMap<Key>*>(obj);
    sleep(2);
    while (dampedMap->IsLooping()) {
        dampedMap->CheckMap();
        sleep(checkTime_);
    }
}

template <class Key>
void DampedMap<Key>::CheckMap()
{
    typename map<Key, DampedData*>::iterator it;
    Lock lock(mapMut_);
    it = dampedMap_.begin();
    for (; it != dampedMap_.end(); ++it) {
        if (it->second->Increase() >= delTimes_) {
            if (it->second->IsUsing()) {
                continue;
            }
            delete it->second;
            clearIt_[clearNum_++] = it;
        }
    }

    for (int i = 0; i < clearNum_; ++i) {
        dampedMap_.erase(clearIt_[i]);
        --dataNum_;
    }
    clearNum_ = 0;
}

#endif

// End of file.
