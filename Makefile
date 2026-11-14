DOTNETFLAGS ?=

build:
	dotnet build src -c Release -o out $(DOTNETFLAGS)

test:
	dotnet build tests -c Release -o tout $(DOTNETFLAGS)
	dotnet tout/Tests.dll

sample: build
	dotnet out/ad-export-audit.dll examples/users.csv --today 2026-03-14 > docs/sample-output.txt
	dotnet out/ad-export-audit.dll examples/users.csv --today 2026-03-14 --html > site/index.html
