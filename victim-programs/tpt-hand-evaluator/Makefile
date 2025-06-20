main: test

HandRanks.dat: generate-table
	./generate-table

handranks.o: HandRanks.dat
	ld -r -b binary HandRanks.dat -o handranks.o

generate-table: *.cpp *.h
	g++ generate_table.cpp  pokerlib.cpp mtrand.cpp -o ./generate-table

test: test.c handranks.o
	gcc -static test.c handranks.o -o victim

clean:
	rm -f *.dat *.o generate-table victim
