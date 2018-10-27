#include "DampedMap.h"

DampedData::DampedData() : dampedCount_(0),
                           using_(false)
{
}

u_short DampedData::Increase()
{
    Lock lock(countMut_);
    return ++dampedCount_;
}

void DampedData::SetZero()
{
    {
        Lock lock(countMut_);
        dampedCount_ = 0;
    }
    using_ = false;
}

void DampedData::Hold()
{
    using_ = true;
}

void DampedData::Release()
{
    using_ = false;
}

bool DampedData::IsUsing()
{
    return using_;
}

