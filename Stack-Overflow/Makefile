all: test

compile:
	gcc -o victim victim.c -fno-stack-protector -no-pie -g

construct:
	python3 main.py

test: compile construct
	cat payload.txt | ./victim

clean:
	rm -rf victim payload.txt
