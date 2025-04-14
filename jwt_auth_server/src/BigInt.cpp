#include "../include/BigInt.h"
#include <sstream>
#include <algorithm>
#include <stdexcept>

BigInt::BigInt() : digits{0}, negative(false) {}

BigInt::BigInt(int value) {
    if (value < 0) {
        negative = true;
        value = -value;
    }
    do {
        digits.push_back(value % 10);
        value /= 10;
    } while (value > 0);
}

BigInt::BigInt(const std::string& str) {
    negative = !str.empty() && str[0] == '-';
    int start = negative ? 1 : 0;
    for (int i = static_cast<int>(str.length()) - 1; i >= start; --i) {
        if (isdigit(str[i]))
            digits.push_back(str[i] - '0');
    }
    if (digits.empty()) digits.push_back(0);
    trim();
}

BigInt::BigInt(const std::string& str, int base) {
    if (base != 10 && base != 16) {
        throw std::invalid_argument("Unsupported base");
    }

    std::string s = str;
    negative = false;

    if (!s.empty() && s[0] == '-') {
        negative = true;
        s = s.substr(1);
    }

    if (base == 10) {
        // обычный десятичный парсинг, переиспользуем текущий конструктор
        *this = BigInt(s);
        if (negative) *this = -(*this);
        return;
    }

    // парсинг hex
    BigInt result;
    BigInt basePow(1);

    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        char c = *it;
        int value = 0;

        if (c >= '0' && c <= '9') value = c - '0';
        else if (c >= 'a' && c <= 'f') value = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') value = 10 + (c - 'A');
        else throw std::invalid_argument("Invalid character in hex string");

        result = result + basePow * BigInt(value);
        basePow = basePow * 16;
    }

    if (negative) result = -result;

    *this = result;
}

std::string BigInt::toString() const {
    std::ostringstream oss;
    if (negative && !isZero()) oss << "-";
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        oss << *it;
    return oss.str();
}

std::string BigInt::toString(int base) const {
    if (base != 10 && base != 16)
        throw std::invalid_argument("Unsupported base");

    if (isZero()) return "0";

    BigInt temp = *this;
    temp.negative = false;

    std::string result;
    BigInt b(base);

    while (!temp.isZero()) {
        BigInt digit = temp % b;
        int d = std::stoi(digit.toString());

        char c;
        if (d < 10) c = '0' + d;
        else c = 'a' + (d - 10);

        result += c;
        temp = temp / b;
    }

    if (negative) result += '-';
    std::reverse(result.begin(), result.end());
    return result;
}

void BigInt::trim() {
    while (digits.size() > 1 && digits.back() == 0)
        digits.pop_back();
    if (digits.size() == 1 && digits[0] == 0)
        negative = false;
}

bool BigInt::isZero() const {
    return digits.size() == 1 && digits[0] == 0;
}

bool BigInt::isNegative() const {
    return negative;
}

int BigInt::compareAbs(const BigInt& a, const BigInt& b) {
    if (a.digits.size() != b.digits.size())
        return a.digits.size() < b.digits.size() ? -1 : 1;
    for (int i = static_cast<int>(a.digits.size()) - 1; i >= 0; --i) {
        if (a.digits[i] != b.digits[i])
            return a.digits[i] < b.digits[i] ? -1 : 1;
    }
    return 0;
}

// Операторы сравнения

bool BigInt::operator==(const BigInt& other) const {
    return negative == other.negative && digits == other.digits;
}

bool BigInt::operator!=(const BigInt& other) const {
    return !(*this == other);
}

bool BigInt::operator<(const BigInt& other) const {
    if (negative != other.negative)
        return negative;
    int cmp = compareAbs(*this, other);
    return negative ? cmp > 0 : cmp < 0;
}

bool BigInt::operator>(const BigInt& other) const {
    return other < *this;
}

bool BigInt::operator<=(const BigInt& other) const {
    return !(*this > other);
}

bool BigInt::operator>=(const BigInt& other) const {
    return !(*this < other);
}

BigInt BigInt::operator-() const {
    BigInt result = *this;
    if (!isZero()) result.negative = !negative;
    return result;
}

// Арифметика

BigInt BigInt::operator+(const BigInt& other) const {
    if (negative == other.negative) {
        BigInt result;
        result.negative = negative;
        result.digits.clear();

        int carry = 0;
        size_t n = std::max(digits.size(), other.digits.size());
        for (size_t i = 0; i < n || carry; ++i) {
            int sum = carry;
            if (i < digits.size()) sum += digits[i];
            if (i < other.digits.size()) sum += other.digits[i];
            result.digits.push_back(sum % 10);
            carry = sum / 10;
        }

        result.trim();
        return result;
    }
    return *this - (-other);
}

BigInt BigInt::operator-(const BigInt& other) const {
    if (negative != other.negative) {
        return *this + (-other);
    }

    if (compareAbs(*this, other) < 0) {
        BigInt result = other - *this;
        result.negative = !negative;
        return result;
    }

    BigInt result;
    result.digits.clear();
    result.negative = negative;

    int borrow = 0;
    for (size_t i = 0; i < digits.size(); ++i) {
        int diff = digits[i] - borrow;
        if (i < other.digits.size()) diff -= other.digits[i];
        if (diff < 0) {
            diff += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result.digits.push_back(diff);
    }

    result.trim();
    return result;
}

BigInt BigInt::operator*(const BigInt& other) const {
    BigInt result;
    result.digits.assign(digits.size() + other.digits.size(), 0);
    result.negative = negative != other.negative;

    for (size_t i = 0; i < digits.size(); ++i) {
        int carry = 0;
        for (size_t j = 0; j < other.digits.size() || carry; ++j) {
            int64_t cur = result.digits[i + j] +
                          digits[i] * 1LL * (j < other.digits.size() ? other.digits[j] : 0) + carry;
            result.digits[i + j] = cur % 10;
            carry = cur / 10;
        }
    }

    result.trim();
    return result;
}

BigInt BigInt::operator/(const BigInt& other) const {
    if (other.isZero()) throw std::domain_error("Division by zero");

    BigInt result, current;
    result.digits.resize(digits.size());
    result.negative = negative != other.negative;

    BigInt abs_this = *this; abs_this.negative = false;
    BigInt abs_other = other; abs_other.negative = false;

    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        current.digits.insert(current.digits.begin(), digits[i]);
        current.trim();

        int x = 0, l = 0, r = 10;
        while (l <= r) {
            int m = (l + r) / 2;
            BigInt t = abs_other * BigInt(m);
            if (t <= current) {
                x = m;
                l = m + 1;
            } else {
                r = m - 1;
            }
        }

        result.digits[i] = x;
        current = current - abs_other * BigInt(x);
    }

    result.trim();
    return result;
}

BigInt BigInt::operator%(const BigInt& other) const {
    return *this - (*this / other) * other;
}

// Быстрое возведение в степень по модулю
BigInt BigInt::modPow(BigInt base, BigInt exp, const BigInt& mod) {
    base = base % mod;
    BigInt result(1);

    while (!exp.isZero()) {
        if (exp.digits[0] % 2 == 1)
            result = (result * base) % mod;
        base = (base * base) % mod;

        // exp = exp / 2
        BigInt half;
        half.digits.clear();
        int carry = 0;
        for (int i = static_cast<int>(exp.digits.size()) - 1; i >= 0; --i) {
            int current = carry * 10 + exp.digits[i];
            half.digits.insert(half.digits.begin(), current / 2);
            carry = current % 2;
        }
        half.trim();
        exp = half;
    }

    return result;
}

BigInt BigInt::gcd(BigInt a, BigInt b) {
    while (!b.isZero()) {
        BigInt temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
