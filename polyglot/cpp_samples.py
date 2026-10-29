"""
polyglot/cpp_samples.py
━━━━━━━━━━━━━━━━━━━━━━━
Preset benchmark and demonstration samples for C++ code analysis.
"""

CPP_SAMPLE_CODES = {
    "C++ Buffer Overflow & Insecure system() Demo": """#include <iostream>
#include <cstring>
#include <cstdlib>

void process_user_data(const char* input_str) {
    char buffer[16];
    // CWE-120: Buffer Overflow via unbounded strcpy
    strcpy(buffer, input_str);
    
    // CWE-78: Insecure Shell Command Execution
    system("echo Audit completed for transaction");
}

int main() {
    process_user_data("this_string_is_much_longer_than_sixteen_characters");
    return 0;
}
""",
    "C++ Broken Syntax / Missing Semicolons (Self-Healing Demo)": """#include <vector>

int calculate_metrics(int factor, int count) {
    int total = 0
    for (int i = 0; i < count; i++) {
        if (i % 2 == 0) {
            total += i * factor
        }
    return total;
}
""",
    "C++ O(N²) Nested Loop Complexity Demo": """#include <iostream>
#include <vector>

int check_duplicates(const std::vector<int>& list_a, const std::vector<int>& list_b) {
    int duplicates = 0;
    // O(N^2) nested loop comparison
    for (size_t i = 0; i < list_a.size(); ++i) {
        for (size_t j = 0; j < list_b.size(); ++j) {
            if (list_a[i] == list_b[j]) {
                duplicates++;
            }
        }
    }
    return duplicates;
}

int main() {
    std::vector<int> a = {1, 2, 3, 4, 5};
    std::vector<int> b = {3, 4, 5, 6, 7};
    std::cout << "Duplicates: " << check_duplicates(a, b) << std::endl;
    return 0;
}
""",
    "C++ Clean RAII & Memory-Safe Logic": """#include <iostream>
#include <vector>
#include <numeric>

double calculate_average(const std::vector<double>& scores) {
    if (scores.empty()) {
        return 0.0;
    }
    double sum = std::accumulate(scores.begin(), scores.end(), 0.0);
    return sum / static_cast<double>(scores.size());
}

int main() {
    std::vector<double> scores = {92.5, 88.0, 95.5, 78.0};
    std::cout << "Class average: " << calculate_average(scores) << std::endl;
    return 0;
}
""",
}
