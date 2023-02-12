add_executable(
  test_merkle

  test_merkle.cpp
)
target_link_libraries(
  test_merkle

  snark
  SEAL::seal
)
add_executable(
  test_service_confirm

  test_confirm.cpp
)
target_link_libraries(
  test_service_confirm

  snark
  SEAL::seal
)
add_executable(
  test_he

  test_he.cpp
)
target_link_libraries(
  test_he

  snark
  SEAL::seal
)