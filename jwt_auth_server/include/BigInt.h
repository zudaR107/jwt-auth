#pragma once
#include <vector>
#include <string>

class BigInt {
public:
    BigInt();                         // 0
    BigInt(int value);                // от int (включая отрицательные)
    BigInt(const std::string& str);   // из строки

    std::string toString() const;

    // Арифметика
    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const;
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;

    // Возведение в степень по модулю
    static BigInt modPow(BigInt base, BigInt exp, const BigInt& mod);
    static BigInt gcd(BigInt a, BigInt b);

    // Сравнение
    bool operator<(const BigInt& other) const;
    bool operator>(const BigInt& other) const;
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;

    BigInt operator-() const; // унарный минус

    bool isZero() const;
    bool isNegative() const;

private:
    std::vector<int> digits; // младший разряд — в начале
    bool negative = false;

    void trim();
    static int compareAbs(const BigInt& a, const BigInt& b); // сравнение по модулю
};
