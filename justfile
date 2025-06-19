# Justfile to make some common tasks in the vodozemac repo easier.

# List the available recipes.
default:
    just --list

# Create a coverage report using llvm-cov.
coverage:
    cargo llvm-cov nextest

# Create a coverage report for codecov.
coverage-codecov:
    cargo llvm-cov nextest --codecov --output-path coverage.xml --profile ci
