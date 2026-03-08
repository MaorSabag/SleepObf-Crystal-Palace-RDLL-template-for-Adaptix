all: clean
	@ echo "    * Building stealthpalace plugin"
	@ mkdir -p dist
	@ cp config.yaml ax_config.axs ./dist/
	
	@ go mod tidy
	
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/stealthpalace.so .
	@ echo "      done..."

clean:
	@ rm -rf dist
