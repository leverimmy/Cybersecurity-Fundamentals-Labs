all: compile

compile:
	javac ./src/**/*.java

A: compile
	java -cp ./src parties.PartyA $(PWD) $(HOST) $(PORT)

B: compile
	java -cp ./src parties.PartyB $(PWD) $(HOST) $(PORT)

clean:
	rm -rf ./src/**/*.class
