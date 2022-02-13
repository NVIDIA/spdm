
#include <array>
#include <cstring>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

TEST(Fake, Pass)
{
    int i = 2;
    EXPECT_EQ(i, 2);
}
