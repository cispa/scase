main: generate-table
	./generate-table

HandRanks.dat: generate-table
	./generate-table

handranks.o: HandRanks.dat
	ld -r -b binary HandRanks.dat -o handranks.o

generate-table: *.cpp *.h
	clang++ generate_table.cpp  pokerlib.cpp mtrand.cpp -o ./generate-table

#test: test.cpp handranks.o
#	g++ test.cpp handranks.o -o test
test: test.c handranks.o
	gcc -static test.c handranks.o -o test

clean:
	rm -f *.dat *.o generate-table test
