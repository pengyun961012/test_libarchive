default: test_archive
test_binary: 
	gcc -Wall -Werror test_archive.c -o test_archive -larchive

clean: 
	rm test_archive