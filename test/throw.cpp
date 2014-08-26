#include <iostream>
#include <stdexcept>

int main()
{
    try {
        throw std::logic_error("dupa");
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
    }
}

