// test_program.cpp - Test program for PDB generation
// This creates a PDB with known symbols for testing pdbsql
//
// Build with: cl /Zi /Fe:test_program.exe test_program.cpp
// Output: test_program.exe, test_program.pdb

#include <cstdint>
#include <cstdio>

// ============================================================================
// Global data symbols
// ============================================================================

int g_global_int = 42;
const char* g_global_string = "Hello PDB";
static double s_static_double = 3.14159;

// ============================================================================
// Enumerations
// ============================================================================

enum Color {
    COLOR_RED = 0,
    COLOR_GREEN = 1,
    COLOR_BLUE = 2
};

enum class Status : uint32_t {
    OK = 0,
    ERROR = 1,
    PENDING = 2
};

// ============================================================================
// Structures and classes
// ============================================================================

struct Point {
    int x;
    int y;
};

struct Rectangle {
    Point top_left;
    Point bottom_right;

    int width() const { return bottom_right.x - top_left.x; }
    int height() const { return bottom_right.y - top_left.y; }
    int area() const { return width() * height(); }
};

class Counter {
public:
    Counter() : m_value(0) {}
    explicit Counter(int initial) : m_value(initial) {}

    void increment() { ++m_value; }
    void decrement() { --m_value; }
    void add(int n) { m_value += n; }
    int get() const { return m_value; }
    void reset() { m_value = 0; }

private:
    int m_value;
};

// ============================================================================
// Template class
// ============================================================================

template<typename T>
class Container {
public:
    Container() : m_data(T{}), m_size(0) {}
    void set(T value) { m_data = value; m_size = 1; }
    T get() const { return m_data; }
    size_t size() const { return m_size; }

private:
    T m_data;
    size_t m_size;
};

// ============================================================================
// Free functions
// ============================================================================

int add_numbers(int a, int b) {
    return a + b;
}

int multiply_numbers(int a, int b) {
    return a * b;
}

double calculate_average(const int* values, size_t count) {
    if (count == 0) return 0.0;
    int sum = 0;
    for (size_t i = 0; i < count; ++i) {
        sum += values[i];
    }
    return static_cast<double>(sum) / count;
}

const char* color_to_string(Color c) {
    switch (c) {
        case COLOR_RED: return "red";
        case COLOR_GREEN: return "green";
        case COLOR_BLUE: return "blue";
        default: return "unknown";
    }
}

// Static function (internal linkage)
static int helper_function(int x) {
    return x * 2;
}

// ============================================================================
// Namespace
// ============================================================================

namespace utils {
    int clamp(int value, int min_val, int max_val) {
        if (value < min_val) return min_val;
        if (value > max_val) return max_val;
        return value;
    }

    namespace math {
        int factorial(int n) {
            if (n <= 1) return 1;
            return n * factorial(n - 1);
        }
    }
}

// ============================================================================
// Virtual functions and inheritance
// ============================================================================

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char* name() const = 0;
};

class Circle : public Shape {
public:
    explicit Circle(double r) : m_radius(r) {}
    double area() const override { return 3.14159 * m_radius * m_radius; }
    const char* name() const override { return "Circle"; }
    double radius() const { return m_radius; }

private:
    double m_radius;
};

class Square : public Shape {
public:
    explicit Square(double s) : m_side(s) {}
    double area() const override { return m_side * m_side; }
    const char* name() const override { return "Square"; }
    double side() const { return m_side; }

private:
    double m_side;
};

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char* argv[]) {
    // Use various symbols to ensure they appear in PDB
    printf("Test program for pdbsql\n");
    printf("g_global_int = %d\n", g_global_int);
    printf("g_global_string = %s\n", g_global_string);

    // Use functions
    int sum = add_numbers(10, 20);
    int product = multiply_numbers(5, 6);
    printf("add_numbers(10, 20) = %d\n", sum);
    printf("multiply_numbers(5, 6) = %d\n", product);

    // Use structs
    Rectangle rect = {{0, 0}, {100, 50}};
    printf("Rectangle area = %d\n", rect.area());

    // Use class
    Counter counter(10);
    counter.increment();
    counter.add(5);
    printf("Counter value = %d\n", counter.get());

    // Use template
    Container<int> container;
    container.set(42);
    printf("Container value = %d\n", container.get());

    // Use enum
    Color c = COLOR_GREEN;
    printf("Color = %s\n", color_to_string(c));

    // Use namespace
    int clamped = utils::clamp(150, 0, 100);
    int fact = utils::math::factorial(5);
    printf("Clamped = %d, Factorial(5) = %d\n", clamped, fact);

    // Use virtual functions
    Circle circle(5.0);
    Square square(4.0);
    Shape* shapes[] = { &circle, &square };
    for (auto* shape : shapes) {
        printf("%s area = %.2f\n", shape->name(), shape->area());
    }

    // Use static function
    int doubled = helper_function(21);
    printf("Helper result = %d\n", doubled);

    return 0;
}
