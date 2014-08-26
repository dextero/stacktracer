#include <iostream>
#include <stdexcept>
#include <vector>

int main()
{
    std::vector<int> test;

    try {
        test.at(0);
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}

