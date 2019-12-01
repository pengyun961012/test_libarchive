default: test_archive
test_archive: 
	gcc -Wall -Werror -o test_archive test_archive.c -larchive
clean: 
	rm test_archive
