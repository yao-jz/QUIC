#ifndef THQUIC_UTILS_INTERVAL_HH
#define THQUIC_UTILS_INTERVAL_HH

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <list>
#include <stdexcept>
#include <string>

namespace thquic::utils {
class Interval {
   public:
    enum class PointCompResult {
        LEFT,
        LEFT_EXTENSIBLE,
        INNER,
        RIGHT_EXTENSIBLE,
        RIGHT
    };
    enum class IntervalCompResult {
        LEFT,
        LEFT_EXTENSIBLE,
        LEFT_INTERSECT,
        INNER,
        RIGHT_INTERSECT,
        RIGHT_EXTENSIBLE,
        RIGHT,
        OUTER
    };

    Interval(uint64_t start, uint64_t end) : start{start}, end{end} {}

    bool Contain(uint64_t v) const {
        return this->PointComp(v) == PointCompResult::INNER;
    }

    bool operator==(const Interval& interval) const {
        return (this->start == interval.start) && (this->end == interval.end);
    }

    // the range of interval is [start, end]
    PointCompResult PointComp(uint64_t n) const {
        if ((this->start != 0) && (n < this->start - 1)) {
            return PointCompResult::LEFT;
        } else if ((this->start != 0) && (n == (this->start - 1))) {
            return PointCompResult::LEFT_EXTENSIBLE;
        } else if (n <= this->end) {
            return PointCompResult::INNER;
        } else if (n == this->end + 1) {
            return PointCompResult::RIGHT_EXTENSIBLE;
        } else {
            return PointCompResult::RIGHT;
        }
    }

    IntervalCompResult RangeComp(const Interval& v) const {
        switch (this->PointComp(v.start)) {
            case PointCompResult::LEFT:
                switch (this->PointComp(v.end)) {
                    case PointCompResult::LEFT:
                        return IntervalCompResult::LEFT;
                    case PointCompResult::LEFT_EXTENSIBLE:
                        return IntervalCompResult::LEFT_EXTENSIBLE;
                    case PointCompResult::INNER:
                        if (this->end == v.end) {
                            return IntervalCompResult::OUTER;
                        } else {
                            return IntervalCompResult::LEFT_INTERSECT;
                        }
                    case PointCompResult::RIGHT_EXTENSIBLE:
                    case PointCompResult::RIGHT:
                        return IntervalCompResult::OUTER;
                    default:
                        throw std::invalid_argument("invariant invalidated");
                }
            case PointCompResult::LEFT_EXTENSIBLE:
                switch (this->PointComp(v.end)) {
                    case PointCompResult::LEFT_EXTENSIBLE:
                        return IntervalCompResult::LEFT_EXTENSIBLE;
                    case PointCompResult::INNER:
                        if (this->end == v.end) {
                            return IntervalCompResult::OUTER;
                        } else {
                            return IntervalCompResult::LEFT_INTERSECT;
                        }
                    case PointCompResult::RIGHT_EXTENSIBLE:
                    case PointCompResult::RIGHT:
                        return IntervalCompResult::OUTER;
                    default:
                        throw std::invalid_argument("invariant invalidated");
                }
            case PointCompResult::INNER:
                switch (this->PointComp(v.end)) {
                    case PointCompResult::INNER:
                        return IntervalCompResult::INNER;
                    case PointCompResult::RIGHT_EXTENSIBLE:
                    case PointCompResult::RIGHT:
                        if (this->start != v.start) {
                            return IntervalCompResult::RIGHT_INTERSECT;
                        } else {
                            return IntervalCompResult::OUTER;
                        }
                    default:
                        throw std::invalid_argument("invariant violated");
                }
            case PointCompResult::RIGHT_EXTENSIBLE:
                switch (this->PointComp(v.end)) {
                    case PointCompResult::RIGHT_EXTENSIBLE:
                    case PointCompResult::RIGHT:
                        return IntervalCompResult::RIGHT_EXTENSIBLE;
                    default:
                        throw std::invalid_argument("invariant violated");
                }
            case PointCompResult::RIGHT:
                switch (this->PointComp(v.end)) {
                    case PointCompResult::RIGHT:
                        return IntervalCompResult::RIGHT;
                    default:
                        throw std::invalid_argument("invariant violated");
                }
        }
        throw std::runtime_error("should not reach here.");
    }

    void Complement(const Interval& range) {
        switch (this->RangeComp(range)) {
            case IntervalCompResult::LEFT:
            case IntervalCompResult::LEFT_EXTENSIBLE:
            case IntervalCompResult::RIGHT_EXTENSIBLE:
            case IntervalCompResult::RIGHT:
                throw std::invalid_argument(
                    "cannot calculate complement of two range without "
                    "intersection");
            case IntervalCompResult::INNER:
                throw std::invalid_argument("get two set");
            case IntervalCompResult::OUTER:
                throw std::invalid_argument("get empty set");
            case IntervalCompResult::LEFT_INTERSECT:
                if (range.end == this->end) {
                    throw std::invalid_argument("get empty set");
                }
                this->start = range.end + 1;
                break;
            case IntervalCompResult::RIGHT_INTERSECT:
                if (range.start == this->start) {
                    throw std::invalid_argument("get empty set");
                }
                this->end = range.start - 1;
                break;
        }
        this->CheckInvariant();
    }

    void Merge(const Interval& range) {
        switch (this->RangeComp(range)) {
            case IntervalCompResult::LEFT:
            case IntervalCompResult::RIGHT:
                throw std::invalid_argument(
                    "cannot merge two range without intersection");
            case IntervalCompResult::LEFT_EXTENSIBLE:
            case IntervalCompResult::LEFT_INTERSECT:
                this->start = range.start;
                break;
            case IntervalCompResult::INNER:
                break;
            case IntervalCompResult::RIGHT_EXTENSIBLE:
            case IntervalCompResult::RIGHT_INTERSECT:
                this->end = range.end;
                break;
            case IntervalCompResult::OUTER:
                this->start = range.start;
                this->end = range.end;
                break;
        }
        this->CheckInvariant();
    }

    void CheckInvariant() { assert(this->start <= this->end); }
    uint64_t Start() const { return this->start; }
    uint64_t End() const { return this->end; }

   private:
    uint64_t start;
    uint64_t end;
};

class IntervalSet {
   public:
    IntervalSet() = default;

    bool operator==(const IntervalSet& other) const {
        return (this->intervals.size() == other.intervals.size()) &&
               (std::mismatch(this->intervals.cbegin(), this->intervals.cend(),
                              other.intervals.cbegin())
                    .first == this->intervals.cend());
    }

    bool Contain(uint64_t v) const {
        return std::find_if(this->intervals.cbegin(), this->intervals.cend(),
                            [v](const Interval& interval) {
                                return interval.Contain(v);
                            }) != this->intervals.cend();
    }

    void AddInterval(uint64_t start, uint64_t end) {
        if (this->intervals.empty()) {
            this->intervals.emplace_back(start, end);
        } else {
            Interval range(start, end);
            auto iter = this->intervals.begin();

            for (;;) {
                if (iter == this->intervals.end()) {
                    this->intervals.insert(iter, range);
                    break;
                }
                switch (iter->RangeComp(range)) {
                    case Interval::IntervalCompResult::RIGHT:
                        this->intervals.insert(iter, range);
                        break;
                    case Interval::IntervalCompResult::RIGHT_EXTENSIBLE:
                    case Interval::IntervalCompResult::RIGHT_INTERSECT:
                        iter->Merge(range);
                        break;
                    case Interval::IntervalCompResult::INNER:
                        break;
                    case Interval::IntervalCompResult::LEFT_EXTENSIBLE:
                    case Interval::IntervalCompResult::LEFT_INTERSECT:
                        iter->Merge(range);
                        this->Maintain(iter);
                        break;
                    case Interval::IntervalCompResult::LEFT:
                        iter++;
                        continue;
                    case Interval::IntervalCompResult::OUTER:
                        iter->Merge(range);
                        this->Maintain(iter);
                        break;
                }
                break;
            }
        }
    }

    void Maintain(std::list<Interval>::iterator iter) {
        auto iterNext = std::next(iter);
        while (iterNext != std::end(this->intervals)) {
            switch (iterNext->RangeComp(*iter)) {
                case Interval::IntervalCompResult::RIGHT:
                    break;
                case Interval::IntervalCompResult::RIGHT_EXTENSIBLE:
                case Interval::IntervalCompResult::RIGHT_INTERSECT:
                    iter->Merge(*iterNext);
                    iterNext = this->intervals.erase(iterNext);
                    continue;
                case Interval::IntervalCompResult::OUTER:
                    iterNext = this->intervals.erase(iterNext);
                    continue;
                default:
                    throw std::runtime_error("invariant violated");
            }
            break;
        }
    }

    void RemoveInterval(uint64_t pktNumMin, uint64_t pktNumMax) {
        Interval interval(pktNumMin, pktNumMax);

        auto iter = std::begin(this->intervals);

        while (iter != std::end(this->intervals)) {
            switch (interval.RangeComp(*iter)) {
                case Interval::IntervalCompResult::RIGHT:
                case Interval::IntervalCompResult::RIGHT_EXTENSIBLE:
                    iter++;
                    continue;
                case Interval::IntervalCompResult::RIGHT_INTERSECT:
                    iter->Complement(interval);
                    iter++;
                    continue;
                case Interval::IntervalCompResult::INNER:
                    iter = this->intervals.erase(iter);
                    continue;
                case Interval::IntervalCompResult::LEFT_INTERSECT:
                    iter->Complement(interval);
                    break;
                case Interval::IntervalCompResult::LEFT_EXTENSIBLE:
                case Interval::IntervalCompResult::LEFT:
                    break;
                case Interval::IntervalCompResult::OUTER: {
                    auto start = iter->Start();
                    auto end = iter->End();

                    iter = this->intervals.erase(iter);

                    if (start < interval.Start()) {
                        Interval rangeFragmentLeft(start, interval.Start() - 1);
                        iter = this->intervals.insert(iter, rangeFragmentLeft);
                    }

                    if (interval.End() < end) {
                        Interval rangeFragmentRight(interval.End() + 1, end);
                        this->intervals.insert(iter, rangeFragmentRight);
                    }
                    break;
                }
            }
            break;
        }
    }

    void AddIntervalSet(const IntervalSet& set) {
        auto iter = this->intervals.begin();
        auto iterOther = set.Intervals().cbegin();

        while (iterOther != set.Intervals().cend()) {
            if (iter == this->intervals.end()) {
                this->intervals.insert(iter, *iterOther);
                iterOther++;
                continue;
            }
            switch (iter->RangeComp(*iterOther)) {
                case Interval::IntervalCompResult::RIGHT:
                    this->intervals.insert(iter, *iterOther);
                    iterOther++;
                    break;
                case Interval::IntervalCompResult::RIGHT_INTERSECT:
                case Interval::IntervalCompResult::RIGHT_EXTENSIBLE:
                    iter->Merge(*iterOther);
                    iterOther++;
                    break;
                case Interval::IntervalCompResult::OUTER:
                case Interval::IntervalCompResult::LEFT_EXTENSIBLE:
                case Interval::IntervalCompResult::LEFT_INTERSECT:
                    iter->Merge(*iterOther);
                    iterOther++;
                    this->Maintain(iter);
                    break;
                case Interval::IntervalCompResult::INNER:
                    iterOther++;
                    break;
                case Interval::IntervalCompResult::LEFT:
                    iter++;
                    break;
            }
        }
    }

    void RemoveIntervalSet(const IntervalSet& set) {
        auto iter = this->intervals.begin();
        auto iterOther = set.Intervals().cbegin();

        while (iter != this->intervals.end() &&
               iterOther != set.Intervals().cend()) {
            switch (iter->RangeComp(*iterOther)) {
                case Interval::IntervalCompResult::LEFT:
                case Interval::IntervalCompResult::LEFT_EXTENSIBLE:
                    iter++;
                    break;
                case Interval::IntervalCompResult::LEFT_INTERSECT:
                    iter->Complement(*iterOther);
                    iter++;
                    break;
                case Interval::IntervalCompResult::INNER: {
                    auto start = iter->Start();
                    auto end = iter->End();
                    iter = this->intervals.erase(iter);
                    if (start < iterOther->Start()) {
                        Interval rangeFragmentLeft(start,
                                                   iterOther->Start() - 1);
                        iter = this->intervals.insert(iter, rangeFragmentLeft);
                    }
                    if (iterOther->End() < end) {
                        Interval rangeFragmentRight(iterOther->End() + 1, end);
                        iter = this->intervals.insert(iter, rangeFragmentRight);
                    }
                    iterOther++;
                    break;
                }
                case Interval::IntervalCompResult::RIGHT:
                case Interval::IntervalCompResult::RIGHT_EXTENSIBLE:
                    iterOther++;
                    break;
                case Interval::IntervalCompResult::RIGHT_INTERSECT:
                    iter->Complement(*iterOther);
                    iterOther++;
                    break;
                case Interval::IntervalCompResult::OUTER:
                    iter = this->intervals.erase(iter);
                    break;
            }
        }
    }

    uint64_t GetStart() const { return this->intervals.back().Start(); }

    uint64_t GetEnd() const { return this->intervals.front().End(); }

    bool Empty() const { return this->intervals.empty(); }

    const std::list<Interval>& Intervals() const { return this->intervals; }

    std::string Dump() const {
        std::string chunksStr = "";
        for (auto& chunk : intervals) {
            chunksStr += "(" + std::to_string(chunk.End()) + " : " +
                         std::to_string(chunk.Start()) + ")";
        }
        return chunksStr;
    }

   private:
    std::list<Interval> intervals;
};

}  // namespace thquic::utils

#endif