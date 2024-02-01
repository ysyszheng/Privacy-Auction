enable_testing()

file(STRINGS params.txt lines)

set(counter 0)
foreach(line IN LISTS lines)
    separate_arguments(line_as_args UNIX_COMMAND "${line}")
    add_test(NAME "Test_${counter}" COMMAND ${PROJECT_NAME} ${line_as_args})
    math(EXPR counter "${counter} + 1")
endforeach()
